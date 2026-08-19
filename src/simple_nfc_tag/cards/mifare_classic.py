"""MIFARE Classic 1K and 4K.

Two things make the Classic different from everything else here.

**Authentication.** A sector answers nothing at all until a key for it has been
proved, and the only way to find the right key is to try one and see. Authentication
is per *sector*, not per block, so the result is worth caching -- the original script
re-authenticated before every single block read, wasting three round trips per sector.
But only **one sector is open at a time**: authenticating the next one closes the
last, so what is cached is the single open sector rather than a set of them.

**Holes in the address space.** The last block of every sector holds the keys, and
writing to it with the wrong bytes bricks the sector permanently. Block 0 holds the
UID and is read-only. Neither ever appears in the user-block list, so the linear tier
above cannot address them even by accident -- and sector 0 is skipped entirely, which
also leaves room for the MAD that MIFARE Classic NDEF will need.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from simple_nfc_tag.cards import register_driver
from simple_nfc_tag.cards.base import Card
from simple_nfc_tag.exceptions import ApduError, AuthenticationError
from simple_nfc_tag.keys import DefaultKeyProvider, KeyProvider

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Sequence

    from simple_nfc_tag.cards.atr import AtrInfo
    from simple_nfc_tag.readers.base import Reader

__all__ = ["Classic1K", "Classic4K", "MifareClassic"]

#: Blocks 0-3 are sector 0: the UID block and the manufacturer data. User data starts
#: at block 4, matching what tags written by the original script already contain.
_FIRST_USER_SECTOR = 1

#: A 4K switches to 16-block sectors above this block address.
_LARGE_SECTOR_FIRST_BLOCK = 128
_SMALL_SECTOR_BLOCKS = 4
_LARGE_SECTOR_BLOCKS = 16

#: The reader key slot this driver loads candidate keys into.
_KEY_SLOT = 0


@register_driver
class MifareClassic(Card):
    """A MIFARE Classic. Instantiated as :class:`Classic1K` or :class:`Classic4K`."""

    product: ClassVar[str] = "MIFARE Classic"
    block_size: ClassVar[int] = 16

    #: Total blocks on the tag, including trailers and block 0.
    total_blocks: ClassVar[int] = 64
    #: PC/SC card name this product reports.
    card_name: ClassVar[int | None] = None

    def __init__(self, reader: Reader, uid: bytes, keys: KeyProvider | None = None) -> None:
        super().__init__(reader, uid)
        self._keys: KeyProvider = keys or DefaultKeyProvider()
        #: The single sector currently authenticated, if any.
        self._open_sector: int | None = None

    @classmethod
    def probe(cls, reader: Reader, atr: AtrInfo, uid: bytes) -> Card | None:
        if cls is not MifareClassic:
            return None
        for driver in (Classic1K, Classic4K):
            if driver.card_name == atr.card_name:
                return driver(reader, uid)
        return None

    # ---------------------------------------------------------------------- keys

    @property
    def keys(self) -> KeyProvider:
        """The key policy used to authenticate sectors."""
        return self._keys

    @keys.setter
    def keys(self, provider: KeyProvider) -> None:
        # A sector opened under the old policy must not stay open under the new one.
        self._keys = provider
        self._open_sector = None

    # ----------------------------------------------------------------- geometry

    @classmethod
    def sector_of(cls, block: int) -> int:
        """Which sector a block address belongs to."""
        if block < _LARGE_SECTOR_FIRST_BLOCK:
            return block // _SMALL_SECTOR_BLOCKS
        return 32 + (block - _LARGE_SECTOR_FIRST_BLOCK) // _LARGE_SECTOR_BLOCKS

    @classmethod
    def is_trailer(cls, block: int) -> bool:
        """Whether a block is a sector trailer, and therefore never user memory."""
        if block < _LARGE_SECTOR_FIRST_BLOCK:
            return block % _SMALL_SECTOR_BLOCKS == _SMALL_SECTOR_BLOCKS - 1
        return (block - _LARGE_SECTOR_FIRST_BLOCK) % _LARGE_SECTOR_BLOCKS == (
            _LARGE_SECTOR_BLOCKS - 1
        )

    def _user_blocks(self) -> Sequence[int]:
        return tuple(
            block
            for block in range(_FIRST_USER_SECTOR * _SMALL_SECTOR_BLOCKS, self.total_blocks)
            if not self.is_trailer(block)
        )

    # ------------------------------------------------------------------- native

    def read_block(self, index: int) -> bytes:
        self._authenticate(index)
        return self._reader.read_binary(index, self.block_size)

    def write_block(self, index: int, data: bytes) -> None:
        if len(data) != self.block_size:
            raise ValueError(f"a Classic block is {self.block_size} bytes, got {len(data)}")
        if self.is_trailer(index):
            raise ValueError(
                f"block {index} is a sector trailer; writing it would change the sector's "
                "keys and can lock the sector permanently"
            )
        self._authenticate(index)
        self._reader.update_binary(index, data)

    # --------------------------------------------------------- authentication

    def _authenticate(self, block: int) -> None:
        """Open the block's sector, unless it is already the open one.

        **A Classic holds exactly one sector open at a time.** Authenticating sector 2
        closes sector 1, and reading a block of sector 1 afterwards answers ``63 00``
        until it is authenticated again -- so what is cached here is the single open
        sector, not a set of them. A failed attempt closes the open sector too, which
        is why the field is cleared before the first candidate is tried rather than
        after the last one fails.

        Caching it still earns its keep: a payload that fits in one sector costs one
        authentication rather than one per block, which is three round trips saved for
        every sector read.

        (Measured on an ACR122U with a Classic 1K: a refused key does *not* deselect
        the tag, so unlike the NTAG probing path this loop needs no session reset
        between candidates.)
        """
        sector = self.sector_of(block)
        if sector == self._open_sector:
            return

        self._open_sector = None

        attempted = []
        for key_type, key in self._keys.keys_for(sector):
            attempted.append(f"{key_type.name}:{key.hex().upper()}")
            self._reader.load_key(_KEY_SLOT, key)
            try:
                self._reader.authenticate(block, key_type, _KEY_SLOT)
            except ApduError:
                continue
            self._open_sector = sector
            return

        raise AuthenticationError(
            f"no key opened sector {sector} of this {self.product}; tried {len(attempted)} "
            f"candidate(s): {', '.join(attempted) if attempted else '<none>'}"
        )

    def _session_restarted(self) -> None:
        # A rebuilt RF session forgets which sector was open. The cache must not go on
        # claiming otherwise, or the next read skips the authentication it needs and
        # answers 63 00 for a reason that looks nothing like the real one.
        self._open_sector = None

    @property
    def authenticated_sector(self) -> int | None:
        """The one sector currently open, or ``None``.

        Singular by necessity: see :meth:`_authenticate`.
        """
        return self._open_sector


class Classic1K(MifareClassic):
    """MIFARE Classic 1K: 15 usable sectors, 720 bytes of user memory."""

    product: ClassVar[str] = "MIFARE Classic 1K"
    total_blocks: ClassVar[int] = 64
    card_name: ClassVar[int | None] = 0x0001


class Classic4K(MifareClassic):
    """MIFARE Classic 4K: 3408 bytes of user memory, in sectors of two sizes."""

    product: ClassVar[str] = "MIFARE Classic 4K"
    total_blocks: ClassVar[int] = 256
    card_name: ClassVar[int | None] = 0x0002
