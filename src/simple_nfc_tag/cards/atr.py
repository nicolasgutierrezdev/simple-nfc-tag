"""Decoding the PC/SC contactless ATR.

A contactless reader synthesises the ATR, with PC/SC Part 3 fixing its contents. Two
bytes matter: the *card name* (MIFARE Classic 1K / 4K / Ultralight) and the *standard*
byte (ISO 14443 A or B).

NTAG213, NTAG215, NTAG216 and plain Ultralight all report card name ``0003``, so
telling them apart needs ``GET_VERSION`` over :meth:`Reader.transceive`.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["CARD_NAMES", "AtrInfo", "parse_atr"]

# Registered application provider identifier of the PC/SC workgroup. The card name
# and standard byte sit immediately behind it.
_PCSC_RID = b"\xa0\x00\x00\x03\x06"

#: Card names from the PC/SC Part 3 supplement, for the tags this package cares about.
CARD_NAMES = {
    0x0001: "MIFARE Classic 1K",
    0x0002: "MIFARE Classic 4K",
    0x0003: "MIFARE Ultralight",
    0x0026: "MIFARE Mini",
    0x0036: "MIFARE Plus SL1 2K",
    0x0037: "MIFARE Plus SL1 4K",
    0x0038: "MIFARE Plus SL2 2K",
    0x0039: "MIFARE Plus SL2 4K",
    0x003A: "MIFARE Ultralight C",
}


@dataclass(frozen=True)
class AtrInfo:
    """What the ATR reports about the tag."""

    #: The 2-byte PC/SC card name, or ``None`` if the ATR does not carry one.
    card_name: int | None
    #: The standard byte: ``0x03`` ISO 14443 A part 3, ``0x11`` Felica, and so on.
    standard: int | None
    raw: bytes

    @property
    def product(self) -> str:
        """A human name for the card, falling back to the raw code."""
        if self.card_name is None:
            return "unknown"
        return CARD_NAMES.get(self.card_name, f"unknown card name 0x{self.card_name:04X}")


def parse_atr(atr: bytes) -> AtrInfo:
    """Pull the card name and standard byte out of a contactless ATR.

    Locates the PC/SC RID directly instead of walking the interface-byte chain: the
    layout behind it (``SS C0 C1``) is fixed, while the framing in front varies between
    readers and firmware revisions. An ATR with no RID is not an error; the caller
    falls back to probing.
    """
    index = atr.find(_PCSC_RID)
    if index < 0 or len(atr) < index + len(_PCSC_RID) + 3:
        return AtrInfo(card_name=None, standard=None, raw=bytes(atr))

    tail = atr[index + len(_PCSC_RID) :]
    return AtrInfo(
        card_name=int.from_bytes(tail[1:3], "big"),
        standard=tail[0],
        raw=bytes(atr),
    )
