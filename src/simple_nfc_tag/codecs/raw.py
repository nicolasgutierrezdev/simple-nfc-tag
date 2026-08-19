"""The raw codec: bytes in, bytes out, no framing at all.

For tags whose layout is decided elsewhere -- a fixed struct, something another system
wrote, the output of the script this package was ported from. Nothing is added, so
nothing identifies it: a raw payload is indistinguishable from an empty tag or from
somebody else's format, which is why ``format="raw"`` has to be given on read as well
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

        There is no length on the tag to say where the payload stops, so everything is
        returned and the caller slices. This is the one read that costs a full drain.
        """
        return cursor.read_rest()

    def detect(self, head: bytes) -> bool:
        """Never claims a payload: raw bytes carry nothing to recognise them by."""
        return False


register_codec(RawCodec())
