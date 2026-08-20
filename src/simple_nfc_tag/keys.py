"""Key material for authenticated tags.

A MIFARE Classic sector answers nothing until a key for it is proved, and a tag cannot
be asked which key it wants. Key handling is therefore an ordered list of candidates,
pluggable because the sensible list depends on where the tags came from.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable, Iterator
from enum import IntEnum

__all__ = [
    "FACTORY_KEY",
    "WELL_KNOWN_KEYS",
    "DefaultKeyProvider",
    "KeyProvider",
    "KeyType",
    "StaticKeyProvider",
]

#: The transport-configuration key every blank MIFARE Classic ships with.
FACTORY_KEY = b"\xff\xff\xff\xff\xff\xff"

#: Keys found on tags that were never personalised: the NDEF public key, the old MAD
#: keys, and a few that ship in sample code.
WELL_KNOWN_KEYS = (
    FACTORY_KEY,
    bytes.fromhex("D3F7D3F7D3F7"),  # NFC Forum public key, used by NDEF-formatted tags
    bytes.fromhex("A0A1A2A3A4A5"),  # MAD key A
    bytes.fromhex("B0B1B2B3B4B5"),
    bytes.fromhex("000000000000"),
    bytes.fromhex("AABBCCDDEEFF"),
)


class KeyType(IntEnum):
    """MIFARE key slot, as encoded in the PC/SC general authenticate APDU."""

    A = 0x60
    B = 0x61


class KeyProvider(abc.ABC):
    """Supplies the keys to try for a sector, in the order to try them."""

    @abc.abstractmethod
    def keys_for(self, sector: int) -> Iterable[tuple[KeyType, bytes]]:
        """Candidate ``(key type, key)`` pairs for one sector, best guess first."""


class DefaultKeyProvider(KeyProvider):
    """Try the factory key as A then B, then the other well-known keys.

    Ordered by likelihood: a wrong candidate costs one round trip per sector.
    """

    def keys_for(self, sector: int) -> Iterator[tuple[KeyType, bytes]]:
        yield KeyType.A, FACTORY_KEY
        yield KeyType.B, FACTORY_KEY
        for key in WELL_KNOWN_KEYS[1:]:
            yield KeyType.A, key
            yield KeyType.B, key


class StaticKeyProvider(KeyProvider):
    """Use one key for every sector, or a per-sector mapping.

    >>> StaticKeyProvider(key=bytes.fromhex("A0A1A2A3A4A5"))          # doctest: +SKIP
    >>> StaticKeyProvider(per_sector={1: bytes.fromhex("FFFFFFFFFF00")})  # doctest: +SKIP
    """

    def __init__(
        self,
        key: bytes | None = None,
        key_type: KeyType = KeyType.A,
        per_sector: dict[int, bytes] | None = None,
    ) -> None:
        if key is None and not per_sector:
            raise ValueError("a StaticKeyProvider needs either a key or a per-sector mapping")
        self.key = key
        self.key_type = key_type
        self.per_sector = dict(per_sector or {})

    def keys_for(self, sector: int) -> Iterator[tuple[KeyType, bytes]]:
        specific = self.per_sector.get(sector)
        if specific is not None:
            yield self.key_type, specific
        if self.key is not None:
            yield self.key_type, self.key
