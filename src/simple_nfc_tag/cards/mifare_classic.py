"""MIFARE Classic 1K and 4K.

Two differences from the rest of the family.

**Authentication.** A sector answers nothing until a key for it is proved, and the
only way to find the key is to try one. Authentication is per sector, not per block,
so it is cached: one authentication per sector instead of one per block. Only one
sector is open at a time, so the cache holds a single sector, not a set.

**Holes in the address space.** The last block of every sector holds the keys, and a
wrong write there bricks the sector permanently. Block 0 holds the UID and is
read-only. Neither appears in the user-block list, and sector 0 is skipped entirely,
which leaves room for the MAD that MIFARE Classic NDEF needs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

from simple_nfc_tag import access_bits
from simple_nfc_tag.access_bits import AccessCondition
from simple_nfc_tag.cards import register_driver
from simple_nfc_tag.cards.base import Card
from simple_nfc_tag.exceptions import ApduError, AuthenticationError, WriteVerificationError
from simple_nfc_tag.keys import DefaultKeyProvider, KeyProvider, KeyType

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Sequence

    from simple_nfc_tag.cards.atr import AtrInfo
    from simple_nfc_tag.readers.base import Reader

__all__ = ["Classic1K", "Classic4K", "MifareClassic", "SectorTrailer"]

#: Blocks 0-3 are sector 0: the UID block and the manufacturer data. User data starts
#: at block 4.
_FIRST_USER_SECTOR = 1

#: A 4K switches to 16-block sectors above this block address.
_LARGE_SECTOR_FIRST_BLOCK = 128
_SMALL_SECTOR_BLOCKS = 4
_LARGE_SECTOR_BLOCKS = 16

#: The reader key slot this driver loads candidate keys into.
_KEY_SLOT = 0

#: Length of a Classic key, and of the whole trailer.
_KEY_LEN = 6
_TRAILER_LEN = 16


@dataclass(frozen=True)
class SectorTrailer:
    """A decoded sector trailer.

    ``key_a`` always reads back as zeros from a real tag: key A is write-only under
    every access condition. To tell whether a trailer write landed, look at
    :attr:`access`, never at the keys.
    """

    #: Key A as it read back: zeros on real silicon, whatever was written on the fake.
    key_a: bytes
    #: The four blocks' access conditions: three data blocks then the trailer itself.
    access: tuple[AccessCondition, AccessCondition, AccessCondition, AccessCondition]
    #: The general-purpose byte (byte 9), free for application use.
    gpb: int
    #: Key B, readable only under some access conditions; zeros otherwise.
    key_b: bytes


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

    @classmethod
    def _sector_bounds(cls, sector: int) -> tuple[int, int]:
        """The first block of a sector and how many blocks it has.

        A 4K keeps four-block sectors up to sector 31, then switches to sixteen.
        """
        small_sectors = _LARGE_SECTOR_FIRST_BLOCK // _SMALL_SECTOR_BLOCKS
        if sector < small_sectors:
            return sector * _SMALL_SECTOR_BLOCKS, _SMALL_SECTOR_BLOCKS
        first = _LARGE_SECTOR_FIRST_BLOCK + (sector - small_sectors) * _LARGE_SECTOR_BLOCKS
        return first, _LARGE_SECTOR_BLOCKS

    @classmethod
    def trailer_block(cls, sector: int) -> int:
        """The block that holds a sector's keys and access bits."""
        first, count = cls._sector_bounds(sector)
        return first + count - 1

    @property
    def sector_count(self) -> int:
        """How many sectors the tag has."""
        return self.sector_of(self.total_blocks - 1) + 1

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

    # --------------------------------------------------------- keys / trailer

    def read_sector_trailer(self, sector: int) -> SectorTrailer:
        """Read and decode a sector's trailer.

        Authenticates through the usual key policy, then decodes the three access
        bytes, raising :class:`ValueError` if their redundant copies disagree.

        The keys read back as zeros unless the access condition exposes them; use
        :attr:`SectorTrailer.access`.
        """
        block = self.trailer_block(sector)
        self._authenticate(block)
        raw = self._reader.read_binary(block, self.block_size)
        return SectorTrailer(
            key_a=raw[:_KEY_LEN],
            access=access_bits.decode_access_bits(raw[6:9]),
            gpb=raw[9],
            key_b=raw[10:_TRAILER_LEN],
        )

    def write_sector_trailer(
        self,
        sector: int,
        key_a: bytes,
        key_b: bytes,
        access: tuple[AccessCondition, AccessCondition, AccessCondition, AccessCondition],
        gpb: int = 0x00,
        *,
        i_understand_this_can_brick_the_sector: bool = False,
    ) -> None:
        """Rewrite a sector's keys and access bits. **This can brick the sector.**

        A trailer write has no undo: a wrong key, or an access condition that locks
        reads and writes behind a key you do not have, leaves a sector no key will open
        again. Two guards:

        * Nothing is written unless ``i_understand_this_can_brick_the_sector=True``.
        * An ``access`` leaving a *data* block readable and writable by no key is
          refused outright, flag or not. A *frozen trailer* (keys that can never change
          again) is allowed: that is a normal read-only configuration.

        After the write the trailer is re-read on a fresh authentication with the new
        key A and the access bytes compared, raising :class:`WriteVerificationError` if
        they did not land.

        :param access: the four blocks' conditions: three data blocks then the trailer.
            Constants live in :mod:`simple_nfc_tag.access_bits`.
        :param gpb: the general-purpose byte (byte 9); ``0x00`` by default.
        """
        if not i_understand_this_can_brick_the_sector:
            raise ValueError(
                "writing a sector trailer can brick the sector permanently; pass "
                "i_understand_this_can_brick_the_sector=True to confirm you mean to"
            )
        if len(key_a) != _KEY_LEN or len(key_b) != _KEY_LEN:
            raise ValueError(f"a Classic key is {_KEY_LEN} bytes")
        if not 0 <= gpb <= 0xFF:
            raise ValueError(f"the general-purpose byte is one byte: {gpb}")

        # encode_access_bits validates each condition; the dead-block check adds the
        # semantic guard on top.
        access_bytes = access_bits.encode_access_bits(*access)
        dead = access_bits.first_dead_data_block(access)
        if dead is not None:
            raise ValueError(
                f"access condition {access[dead]} leaves data block {dead} of sector "
                f"{sector} readable and writable by no key; that would brick it"
            )

        trailer = bytes(key_a) + access_bytes + bytes([gpb]) + bytes(key_b)
        block = self.trailer_block(sector)
        self._authenticate(block)
        self._reader.update_binary(block, trailer)
        self._verify_trailer(block, sector, key_a, access_bytes + bytes([gpb]))

    def set_sector_keys(
        self,
        sector: int,
        key_a: bytes,
        key_b: bytes,
        *,
        access: tuple[AccessCondition, AccessCondition, AccessCondition, AccessCondition] = (
            access_bits.TRANSPORT_DATA,
            access_bits.TRANSPORT_DATA,
            access_bits.TRANSPORT_DATA,
            access_bits.TRANSPORT_TRAILER,
        ),
        gpb: int = 0x00,
        i_understand_this_can_brick_the_sector: bool = False,
    ) -> None:
        """Set a sector's keys, leaving every block freely readable and writable.

        :meth:`write_sector_trailer` with the transport access condition: data blocks
        open to both keys, key A able to rewrite the trailer again. The keyword flag is
        still required.
        """
        self.write_sector_trailer(
            sector,
            key_a,
            key_b,
            access,
            gpb,
            i_understand_this_can_brick_the_sector=i_understand_this_can_brick_the_sector,
        )

    def _verify_trailer(
        self, block: int, sector: int, key_a: bytes, expected_access: bytes
    ) -> None:
        """Re-read the access bytes on a fresh session and confirm they landed.

        The keys just changed, so the open authentication used the old ones. Key A can
        read the access bits under every condition, so proving the new key A and
        comparing bytes 6-9 works whatever was written. Only the access bytes and the
        GPB are checked; the keys read back as zeros.
        """
        self._reader.reset_card_connection()
        self._session_restarted()
        self._reader.load_key(_KEY_SLOT, bytes(key_a))
        try:
            self._reader.authenticate(block, KeyType.A, _KEY_SLOT)
            actual = self._reader.read_binary(block, self.block_size)[6:10]
        except ApduError as exc:
            raise WriteVerificationError(block * self.block_size + 6, expected_access, b"") from exc
        self._open_sector = sector
        if actual != expected_access:
            raise WriteVerificationError(block * self.block_size + 6, expected_access, actual)

    # --------------------------------------------------------- authentication

    def _authenticate(self, block: int) -> None:
        """Open the block's sector, unless it is already the open one.

        A Classic holds exactly one sector open at a time: authenticating sector 2
        closes sector 1, and a later read of sector 1 answers ``63 00``. A failed
        attempt closes the open sector too, so the cache is cleared before the first
        candidate rather than after the last failure.

        Measured on an ACR122U with a Classic 1K: a refused key does not deselect the
        tag, so this loop needs no session reset between candidates.
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
        # A rebuilt RF session forgets which sector was open; a stale cache would make
        # the next read skip the authentication it needs and answer 63 00.
        self._open_sector = None

    @property
    def authenticated_sector(self) -> int | None:
        """The one sector currently open, or ``None``. See :meth:`_authenticate`."""
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
