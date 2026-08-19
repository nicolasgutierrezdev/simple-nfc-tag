"""The :class:`Card` abstraction.

Three tiers, deliberately named so the escape hatches are obvious:

* **native** -- :meth:`Card.read_block` / :meth:`Card.write_block`, in whatever unit
  the tag actually addresses (16-byte Classic blocks, 4-byte Ultralight pages);
* **linear** -- :meth:`Card.read_bytes` / :meth:`Card.write_bytes`, one flat byte
  range over user memory only. This is the seam codecs sit on, and the reason they
  never have to know what a sector trailer is;
* **high level** -- ``read()`` / ``write()``, which hand the linear tier to a codec.
  Those arrive with the codecs.

The linear tier is implemented once, here, in terms of a subclass-supplied list of
user blocks. That list is where every tag's quirks live: Ultralight starts at page 4,
Classic starts at block 4 *and* skips a trailer every fourth block. Expressing the
layout as data rather than as arithmetic is what keeps a trailer from ever being
written by accident.
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING, Any, ClassVar

from simple_nfc_tag.codecs.base import ByteCursor, codec_for, decode_auto
from simple_nfc_tag.exceptions import ApduError, CardFull, WriteVerificationError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Sequence

    from simple_nfc_tag.cards.atr import AtrInfo
    from simple_nfc_tag.readers.base import Reader

__all__ = ["Card"]


class Card(abc.ABC):
    """A tag on a reader.

    A ``Card`` is scoped to one card presence: it holds no state that survives the tag
    leaving the field, and the reader hands out a fresh one when a different UID shows
    up.
    """

    #: Human-readable product name, e.g. ``NTAG213``.
    product: ClassVar[str] = "unknown"
    #: Size of one natively addressable unit, in bytes.
    block_size: ClassVar[int] = 4

    def __init__(self, reader: Reader, uid: bytes) -> None:
        self._reader = reader
        self._uid = bytes(uid)

    def __repr__(self) -> str:
        return f"<{self.product} uid={self._uid.hex().upper()} user_size={self.user_size}>"

    @property
    def uid(self) -> bytes:
        """The tag's unique identifier, 4 or 7 bytes."""
        return self._uid

    @property
    def reader(self) -> Reader:
        """The reader this tag is sitting on."""
        return self._reader

    @property
    def user_size(self) -> int:
        """Bytes of user memory, excluding anything the tag reserves for itself."""
        return len(self._user_blocks()) * self.block_size

    # -------------------------------------------------------------- identification

    @classmethod
    def probe(cls, reader: Reader, atr: AtrInfo, uid: bytes) -> Card | None:
        """Claim the tag in the field, or return ``None`` to let another driver try.

        Called by :func:`simple_nfc_tag.cards.identify` in registration order. A driver
        that recognises the tag returns a constructed instance; the default is to claim
        nothing.
        """
        return None

    # ------------------------------------------------------------------- native

    @abc.abstractmethod
    def read_block(self, index: int) -> bytes:
        """Read one natively addressed block or page, by absolute tag address."""

    @abc.abstractmethod
    def write_block(self, index: int, data: bytes) -> None:
        """Write one natively addressed block or page, by absolute tag address."""

    @abc.abstractmethod
    def _user_blocks(self) -> Sequence[int]:
        """Absolute addresses of the blocks holding user data, in order.

        Reserved blocks -- Classic's block 0 and its sector trailers, Ultralight's
        lock and OTP pages -- are simply absent from this list, so no arithmetic in
        the linear tier can reach them.
        """

    # ------------------------------------------------------------------- linear

    def read_bytes(self, offset: int, length: int) -> bytes:
        """Read ``length`` bytes from user memory, starting at ``offset``.

        Offsets are into a flat user-memory space: byte 0 is the first byte the caller
        owns, whatever its physical address happens to be.
        """
        if offset < 0:
            raise ValueError(f"offset cannot be negative: {offset}")
        if length < 0:
            raise ValueError(f"length cannot be negative: {length}")
        if length == 0:
            return b""
        if offset + length > self.user_size:
            raise CardFull(offset + length, self.user_size)

        blocks = self._user_blocks()
        first = offset // self.block_size
        last = (offset + length - 1) // self.block_size

        data = self._read_run(blocks[first : last + 1])
        start = offset % self.block_size
        return data[start : start + length]

    def write_bytes(self, offset: int, data: bytes, verify: bool = True) -> None:
        """Write ``data`` into user memory at ``offset``.

        Writes are block-granular on the wire, so a write that starts or ends mid-block
        reads the affected block first and merges -- the read-modify-write an Ultralight
        needs for any payload that is not a multiple of its 4-byte page.

        :param verify: read the bytes back afterwards and compare, raising
            :class:`WriteVerificationError` if the tag does not hold what was sent.
            On by default, because a refused write is **not** reliably reported: on an
            NTAG it answers ``90 00`` and quietly changes nothing. Pass ``False`` to
            skip the read-back where the round trips matter more than the certainty.
        """
        if offset < 0:
            raise ValueError(f"offset cannot be negative: {offset}")
        if not data:
            return
        if offset + len(data) > self.user_size:
            raise CardFull(offset + len(data), self.user_size)

        blocks = self._user_blocks()
        first = offset // self.block_size
        last = (offset + len(data) - 1) // self.block_size

        cursor = 0
        for slot in range(first, last + 1):
            block = blocks[slot]
            block_start = slot * self.block_size
            start = max(offset - block_start, 0)
            end = min(offset + len(data) - block_start, self.block_size)
            chunk = data[cursor : cursor + (end - start)]
            cursor += len(chunk)

            if end - start == self.block_size:
                self.write_block(block, chunk)
            else:
                # Partial block: keep the bytes the caller did not address.
                current = bytearray(self.read_block(block))
                current[start:end] = chunk
                self.write_block(block, bytes(current))

        if verify:
            self._verify_write(offset, data)

    # --------------------------------------------------------------- high level

    def write(self, value: Any, format: str = "tlv", verify: bool = True) -> None:
        """Write a value to the tag.

        >>> tag.write(["ABC123", 42])          # doctest: +SKIP
        >>> tag.write(b"raw bytes", format="raw")   # doctest: +SKIP

        The payload is checked against the tag's capacity before a single byte is sent,
        so a value that does not fit leaves what is already on the tag untouched rather
        than half-overwritten.
        """
        payload = codec_for(format).encode(value)
        if len(payload) > self.user_size:
            raise CardFull(len(payload), self.user_size)
        self.write_bytes(0, payload, verify=verify)

    def read(self, format: str | None = None) -> Any:
        """Read the tag's payload.

        With no ``format``, the format is worked out from what is on the tag: a
        proprietary TLV block decodes as ``tlv``, an NDEF message raises
        :class:`NdefNotSupported` rather than producing nonsense, and anything else
        raises :class:`UnknownFormat`. ``raw`` is never detected -- it carries nothing
        to detect -- so reading raw bytes means asking for them by name.
        """
        cursor = ByteCursor(self.read_bytes, self.user_size, chunk=self.block_size)
        if format is not None:
            return codec_for(format).decode(cursor)
        return decode_auto(cursor, self.product)

    # ---------------------------------------------------------------- internals

    def _verify_write(self, offset: int, data: bytes) -> None:
        """Read back what was just written and compare it, byte for byte.

        Comparing bytes rather than reading a status word is deliberate. The obvious
        cheaper guard -- one read after the run, treating ``63 00`` as "something
        failed" -- only works because a refusal deselects an NTAG, and nothing
        deselects a Classic: there the probe would answer ``90 00`` unconditionally
        and report all-clear by construction. Asking the tag what it actually holds
        depends on none of that, and is the only form that can say *which* bytes are
        wrong.
        """
        try:
            actual = self.read_bytes(offset, len(data))
        except ApduError:
            # On an NTAG the refusal that lost the write also deselected the tag, so
            # this read is the command that trips over it. Rebuild the session and ask
            # again: what the caller needs to hear is which bytes are wrong, not that
            # a read failed.
            if not self._reader.reset_card_connection():
                raise
            self._session_restarted()
            actual = self.read_bytes(offset, len(data))

        if actual != data:
            raise WriteVerificationError(offset, data, actual)

    def _session_restarted(self) -> None:  # noqa: B027 - an optional hook, not abstract
        """Drop anything cached that belonged to the RF session, not to the silicon.

        A no-op here, since the base card caches nothing per session; a Classic
        overrides it, because a rebuilt session forgets which sector was open.
        """


    def _read_run(self, blocks: Sequence[int]) -> bytes:
        """Read a run of blocks, one at a time.

        Overridden where the reader can fetch several blocks per APDU -- an Ultralight
        read returns four pages whether you want them or not, and using that turns a
        16-byte read into one exchange instead of four.
        """
        return b"".join(self.read_block(block) for block in blocks)
