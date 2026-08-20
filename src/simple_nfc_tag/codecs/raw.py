"""The raw codec: bytes in, bytes out, no framing.

For tags whose layout is decided elsewhere: a fixed struct, or something another
system wrote. Nothing is added, so nothing identifies it, and a raw payload is
indistinguishable from an empty tag. ``format="raw"`` has to be given on read as well
as on write.
"""

from __future__ import annotations

from typing import Any

from simple_nfc_tag.codecs.base import ByteCursor, register_codec

__all__ = ["RawCodec"]


class RawCodec:
    """Writes bytes verbatim from the first byte of user memory."""

    name = "raw"

    def encode(self, value: Any) -> bytes:
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise TypeError(
                f"the raw format takes bytes, not {type(value).__name__}; use the tlv "
                "format for typed values"
            )
        return bytes(value)

    def decode(self, cursor: ByteCursor) -> bytes:
        """Return the whole of user memory.

        Nothing on the tag says where the payload stops, so the caller slices. The one
        read that costs a full drain.
        """
        return cursor.read_rest()

    def detect(self, head: bytes) -> bool:
        """Never claims a payload: raw bytes carry nothing to recognise."""
        return False


register_codec(RawCodec())
