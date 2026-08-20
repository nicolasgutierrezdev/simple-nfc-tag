"""Payload framing.

Codecs sit on the linear tier of a card and never see a block, a page or a sector. Two
ship with v1:

* ``tlv``: a sequence of typed Python values, self-describing. The default.
* ``raw``: bytes verbatim, for layouts decided elsewhere.

An NDEF codec is designed for but not implemented. It drops in as another codec, and
tags written by v1 stay readable, because a read with no ``format=`` dispatches on
what is on the tag.
"""

from __future__ import annotations

from simple_nfc_tag.codecs.base import (
    ByteCursor,
    Codec,
    codec_for,
    detect_codec,
    known_codecs,
    register_codec,
)
from simple_nfc_tag.codecs.raw import RawCodec
from simple_nfc_tag.codecs.tlv import CompactTlvCodec
from simple_nfc_tag.codecs.values import I8, I16, I32, I64, U8, U16, U32, U64

__all__ = [
    "I8",
    "I16",
    "I32",
    "I64",
    "U8",
    "U16",
    "U32",
    "U64",
    "ByteCursor",
    "Codec",
    "CompactTlvCodec",
    "RawCodec",
    "codec_for",
    "detect_codec",
    "known_codecs",
    "register_codec",
]
