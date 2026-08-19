"""The compact TLV codec: a sequence of typed values in as few bytes as possible.

A tag holds a *sequence*, so ``write(["ABC123", 42])`` gives ``read() -> ["ABC123", 42]``.
Values are typed automatically; wrap one in :class:`~simple_nfc_tag.codecs.values.U16`
and friends when the width has to be pinned rather than minimal.

Inner and outer lengths follow the same rule, the one in
:mod:`~simple_nfc_tag.codecs.framing`.

On the wire::

    FD                        proprietary TLV, outer framing
    0A                        outer length, Type-2 rule
    01 06 41 42 43 31 32 33   inner: T=str, length 6, "ABC123"
    02 02 00 2A               inner: T=u16, length 2, U16(42)
    FE                        terminator

Fifteen bytes to hold a six-character string and a number, of which three are the
framing that keeps the tag a valid Type-2 TLV stream.
"""

from __future__ import annotations

from typing import Any

from simple_nfc_tag.codecs import framing, values
from simple_nfc_tag.codecs.base import ByteCursor, register_codec
from simple_nfc_tag.exceptions import DecodeError, NdefNotSupported

__all__ = ["CompactTlvCodec"]

#: Values of these types are one value, not a sequence of them, even though Python
#: will happily iterate them.
_SCALARS = (str, bytes, bytearray)


class CompactTlvCodec:
    """Encodes a sequence of typed values inside a proprietary Type-2 TLV block."""

    name = "tlv"

    def encode(self, value: Any) -> bytes:
        """Frame a value, or a sequence of values, for writing at offset 0.

        A bare value is treated as a one-element sequence, so ``write("hello")`` and
        ``write(["hello"])`` put the same bytes on the tag. :meth:`decode` always hands
        back a list, which is the price of the tag holding a sequence at all.
        """
        items = self._as_sequence(value)

        body = bytearray()
        for item in items:
            type_id, payload = values.encode_value(item)
            body += bytes([type_id]) + framing.encode_length(len(payload)) + payload

        return framing.encode_block(framing.PROPRIETARY, bytes(body)) + bytes([framing.TERMINATOR])

    def decode(self, cursor: ByteCursor) -> list[Any]:
        """Read the sequence back."""
        block = _find_proprietary_block(cursor)
        return list(_decode_values(block))

    def detect(self, head: bytes) -> bool:
        """A proprietary TLV, possibly behind some NULL padding."""
        for byte in head:
            if byte == framing.NULL:
                continue
            return byte == framing.PROPRIETARY
        return False

    @staticmethod
    def _as_sequence(value: Any) -> list[Any]:
        if isinstance(value, _SCALARS):
            return [value]
        if isinstance(value, (list, tuple)):
            return list(value)
        return [value]


def _find_proprietary_block(cursor: ByteCursor) -> bytes:
    """Walk the TLV stream to the proprietary block and return its value."""
    while cursor.remaining:
        tag = cursor.read(1)[0]

        if tag == framing.NULL:
            continue
        if tag == framing.TERMINATOR:
            raise DecodeError("reached the end of the TLV stream without a payload")

        head = cursor.peek(3)
        length, consumed = framing.decode_length(head, 0)
        cursor.skip(consumed)

        if tag == framing.PROPRIETARY:
            return cursor.read(length)

        if tag == framing.NDEF:
            raise NdefNotSupported

        # Some other TLV: step over it and keep looking.
        cursor.skip(length)

    raise DecodeError("no TLV payload found in user memory")


def _decode_values(block: bytes) -> list[Any]:
    """Split a proprietary block into its inner values."""
    decoded: list[Any] = []
    offset = 0
    while offset < len(block):
        type_id = block[offset]
        length, offset = framing.decode_length(block, offset + 1)
        end = offset + length
        if end > len(block):
            raise DecodeError(
                f"inner value of type 0x{type_id:02X} claims {length} bytes but only "
                f"{len(block) - offset} are left in the payload"
            )
        decoded.append(values.decode_value(type_id, block[offset:end]))
        offset = end
    return decoded


register_codec(CompactTlvCodec())
