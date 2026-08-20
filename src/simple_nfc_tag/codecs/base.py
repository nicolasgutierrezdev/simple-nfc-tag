"""The codec seam, and the lazy cursor codecs read through.

A codec turns Python values into the bytes in user memory and back. It never sees a
block, a page or a sector, only a flat byte stream and an offset.

Reading goes through :class:`ByteCursor` rather than a ``bytes``, so a read fetches
only what the payload needs: a codec reads a tag and a length before it knows how much
more to ask for. Draining an 888-byte NTAG216 for a 12-byte payload would cost 56
exchanges instead of one.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

from simple_nfc_tag.codecs.framing import NDEF, NULL
from simple_nfc_tag.exceptions import DecodeError, NdefNotSupported, UnknownFormat

__all__ = [
    "ByteCursor",
    "Codec",
    "codec_for",
    "decode_auto",
    "detect_codec",
    "known_codecs",
    "register_codec",
]


class ByteCursor:
    """A forward-only reader over a byte range, fetching in chunks.

    :param fetch: called as ``fetch(offset, length)``; normally
        :meth:`Card.read_bytes`.
    :param size: total bytes available.
    :param chunk: minimum fetch size. A card passes its block size, so a fetch never
        costs a partial block.
    """

    def __init__(
        self,
        fetch: Callable[[int, int], bytes],
        size: int,
        chunk: int = 16,
    ) -> None:
        self._fetch = fetch
        self._size = size
        self._chunk = max(1, chunk)
        self._buffer = bytearray()
        #: Offset of the first byte held in the buffer.
        self._buffer_start = 0
        self._position = 0
        #: Bytes actually fetched, so tests can assert a read did not drain the tag.
        self.fetched = 0

    def __repr__(self) -> str:
        return f"<ByteCursor at {self._position} of {self._size}>"

    @property
    def position(self) -> int:
        """How far into the stream the cursor has been advanced."""
        return self._position

    @property
    def remaining(self) -> int:
        """Bytes left between the cursor and the end of the range."""
        return self._size - self._position

    def peek(self, length: int) -> bytes:
        """Look at the next ``length`` bytes without advancing.

        Returns fewer bytes than asked for at the end of the range rather than
        raising.
        """
        wanted = min(length, self.remaining)
        if wanted <= 0:
            return b""
        self._ensure(wanted)
        start = self._position - self._buffer_start
        return bytes(self._buffer[start : start + wanted])

    def read(self, length: int) -> bytes:
        """Consume and return the next ``length`` bytes."""
        if length < 0:
            raise ValueError(f"length cannot be negative: {length}")
        if length > self.remaining:
            raise DecodeError(
                f"payload claims {length} more bytes but only {self.remaining} are "
                "left in user memory"
            )
        data = self.peek(length)
        self._position += length
        return data

    def skip(self, length: int) -> None:
        """Advance without returning anything."""
        self._position = min(self._position + length, self._size)

    def read_rest(self) -> bytes:
        """Consume everything left."""
        return self.read(self.remaining)

    def _ensure(self, length: int) -> None:
        """Make sure the buffer holds ``length`` bytes from the current position."""
        held = self._buffer_start + len(self._buffer) - self._position
        if held >= length:
            return

        # Round the request up to a whole chunk, so a byte-at-a-time parse does not
        # become a fetch-at-a-time parse.
        want = max(length, self._chunk)
        want = min(want, self.remaining)
        data = self._fetch(self._position, want)
        if len(data) < want:  # pragma: no cover - a card that under-delivers
            raise DecodeError(f"asked the tag for {want} bytes and got {len(data)}")

        self._buffer = bytearray(data)
        self._buffer_start = self._position
        self.fetched += len(data)


@runtime_checkable
class Codec(Protocol):
    """Turns values into tag bytes and back."""

    name: str

    def encode(self, value: Any) -> bytes:
        """Bytes to write from the first byte of user memory."""
        ...

    def decode(self, cursor: ByteCursor) -> Any:
        """Read a value from user memory."""
        ...

    def detect(self, head: bytes) -> bool:
        """Whether this codec recognises a payload from its first few bytes.

        A codec whose format is not self-describing answers ``False`` and can only be
        used when named explicitly.
        """
        ...


_CODECS: dict[str, Codec] = {}


#: What :func:`register_codec` insists on before a codec enters the registry.
_REQUIRED = ("name", "encode", "decode", "detect")


def register_codec(codec: Codec) -> Codec:
    """Add a codec under its ``name``.

    The shape is checked here rather than at first use. A codec missing ``detect``
    registers fine and then breaks every later ``read()`` with no ``format=`` — on
    tags it has nothing to do with — as an ``AttributeError`` from inside
    :func:`detect_codec`, a long way from the registration that caused it.
    """
    missing = [attr for attr in _REQUIRED if not hasattr(codec, attr)]
    if missing:
        raise TypeError(
            f"{type(codec).__name__} is not a codec: missing {', '.join(missing)}. "
            "A codec needs a 'name' and encode/decode/detect methods."
        )
    if not isinstance(codec.name, str) or not codec.name:
        raise TypeError(f"a codec's name must be a non-empty string, got {codec.name!r}")
    if codec.name in _CODECS:
        raise ValueError(f"a codec named {codec.name!r} is already registered")
    _CODECS[codec.name] = codec
    return codec


def known_codecs() -> dict[str, Codec]:
    """Registered codecs, by name."""
    return dict(_CODECS)


def codec_for(name: str) -> Codec:
    """Look a codec up by name."""
    try:
        return _CODECS[name]
    except KeyError:
        raise UnknownFormat(
            f"no codec named {name!r}; available formats are "
            + ", ".join(repr(key) for key in sorted(_CODECS))
        ) from None


def detect_codec(head: bytes) -> Codec | None:
    """The codec that claims a payload, or ``None`` if nothing recognises it."""
    for codec in _CODECS.values():
        if codec.detect(head):
            return codec
    return None


def decode_auto(cursor: ByteCursor, product: str = "tag") -> Any:
    """Decode a payload by working out its format from the bytes themselves.

    Makes ``format=`` optional on a read: the answer comes from the tag rather than
    from an argument the caller has to remember.
    """
    head = cursor.peek(min(8, cursor.remaining))

    first = next((byte for byte in head if byte != NULL), None)
    if first == NDEF:
        # Recognised, deliberately not decoded.
        raise NdefNotSupported

    codec = detect_codec(head)
    if codec is None:
        raise UnknownFormat(
            f"nothing on this {product} looks like a payload this package wrote "
            f"(user memory starts {head.hex(' ').upper() or '<empty>'}); pass "
            "format='raw' to read the bytes as they are"
        )
    return codec.decode(cursor)
