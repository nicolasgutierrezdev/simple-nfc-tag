"""Outer framing: the NFC Forum Type-2 TLV stream.

User memory on a Type-2 tag is a sequence of TLV blocks, and this package writes into
that structure rather than over it. A compact-TLV payload travels inside a proprietary
block (``0xFD``). Three bytes of overhead: the tag stays a well-formed TLV stream other
NFC software can walk past, and reading dispatches on the block tag rather than on an
argument.

The length rule lives here and covers both tiers, the TLV blocks in this module and the
typed values inside them: one byte for ``0x00``-``0xFE``, or ``0xFF`` followed by two
big-endian bytes. The inner tier used BER (ISO 7816-4) until it was unified; do not
reintroduce a second convention.
"""

from __future__ import annotations

from simple_nfc_tag.exceptions import DecodeError

__all__ = [
    "NDEF",
    "NULL",
    "PROPRIETARY",
    "TERMINATOR",
    "decode_length",
    "encode_block",
    "encode_length",
    "parse_length",
]

#: Padding. One byte, no length, no value; skip it.
NULL = 0x00
#: An NDEF message. Not decoded by this version, but recognised so the failure is clear.
NDEF = 0x03
#: Proprietary data: where this package's compact TLV payload lives.
PROPRIETARY = 0xFD
#: End of the TLV stream. Everything after it is stale.
TERMINATOR = 0xFE

#: A length of 0xFF is an escape, not a length: two big-endian bytes follow.
_LONG_FORM = 0xFF
_MAX_SHORT = 0xFE
_MAX_LONG = 0xFFFF


def encode_length(length: int) -> bytes:
    """Encode a Type-2 TLV length."""
    if length < 0:
        raise ValueError(f"length cannot be negative: {length}")
    if length <= _MAX_SHORT:
        return bytes([length])
    if length > _MAX_LONG:
        raise ValueError(f"a Type-2 TLV cannot carry {length} bytes")
    return bytes([_LONG_FORM]) + length.to_bytes(2, "big")


def decode_length(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a Type-2 TLV length, returning ``(length, offset just past it)``."""
    if offset >= len(data):
        raise DecodeError("ran out of bytes where a TLV length was expected")

    first = data[offset]
    if first != _LONG_FORM:
        return first, offset + 1
    if offset + 3 > len(data):
        raise DecodeError("a three-byte TLV length is cut short")
    return int.from_bytes(data[offset + 1 : offset + 3], "big"), offset + 3


def parse_length(head: bytes) -> tuple[int, int]:
    """How long the value is, and how many bytes the length itself took.

    A reader working from a tag needs the skip distance before it has the whole block.
    """
    length, end = decode_length(head, 0)
    return length, end


def encode_block(tag: int, value: bytes) -> bytes:
    """Build one TLV block, terminator included where the tag needs none.

    ``NULL`` and ``TERMINATOR`` are single bytes with no length and no value; every
    other tag carries both.
    """
    if not 0 <= tag <= 0xFF:
        raise ValueError(f"TLV tag out of range: {tag}")
    if tag in (NULL, TERMINATOR):
        if value:
            raise ValueError(f"TLV 0x{tag:02X} carries no value, got {len(value)} bytes")
        return bytes([tag])
    return bytes([tag]) + encode_length(len(value)) + bytes(value)
