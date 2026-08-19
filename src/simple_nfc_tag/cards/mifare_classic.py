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
#: at block 4, matching what tags written by the original script already contain.
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

    ``key_a`` is included for completeness but is **always zeros as read from a tag**:
    key A is write-only on every access condition, so what comes back where it lives
    says nothing about what is actually stored. To tell whether a trailer write landed,
    look at :attr:`access`, never at the keys -- which is what
    :meth:`MifareClassic.write_sector_trailer` does.
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

        Authenticates the sector through the usual key policy, then decodes the three
        access bytes -- raising :class:`ValueError` if their redundant copies disagree,
        which is how a corrupted trailer shows up rather than as plausible nonsense.

        Remember the keys read back as zeros unless the access condition exposes them;
        :attr:`SectorTrailer.access` is the honest field.
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

        Writing a trailer is the one operation on a Classic with no undo: a wrong key,
        or an access condition that locks reads and writes behind a key you do not
        have, leaves a sector no key will ever open again. Two things guard it.

        *The keyword flag.* Nothing is written unless
        ``i_understand_this_can_brick_the_sector=True`` is passed. It is deliberately
        long and awkward, so a trailer write can never be a typo for
        :meth:`write_block`.

        *The dead-block refusal.* An ``access`` that would leave a **data** block
        readable and writable by no key at all is rejected outright, flag or no flag:
        that state is inert, has no legitimate use, and is exactly what a corrupted
        sector lands in. A *frozen trailer* -- keys that can never change again -- is
        **not** refused: that is a normal read-only configuration, and the keyword flag
        is what acknowledges its permanence.

        After the write the trailer is re-read on a fresh authentication with the new
        key A and the access bytes are compared, raising
        :class:`WriteVerificationError` if they did not land. The bytes are asked of
        the tag rather than inferred from a status word, because a Classic reports a
        refused trailer write locally in a way that does not always reach the air.

        :param access: the four blocks' conditions -- three data blocks then the
            trailer itself. Constants live in :mod:`simple_nfc_tag.access_bits`.
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

        # encode_access_bits validates each condition; the dead-block check is the
        # semantic guard on top of the structural one.
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

        A thin wrapper over :meth:`write_sector_trailer` with the transport access
        condition: data blocks open to both keys, and key A able to rewrite the trailer
        again. The safe default when all you want is to change the keys. The keyword
        flag is still required, since the write is as irreversible as any other.
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
        read the access bits under every access condition, and it is never itself
        readable, so proving the *new* key A and comparing bytes 6-9 is the one check
        that works whatever was written. Only the access bytes and the GPB are checked:
        the keys read back as zeros and cannot be verified from the tag.
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
