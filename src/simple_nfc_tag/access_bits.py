"""MIFARE Classic sector-trailer access bits.

A sector trailer is sixteen bytes: key A, three access-condition bytes, a
general-purpose byte, key B. The access bytes encode, for each of the sector's four
blocks, a three-bit condition ``(C1, C2, C3)``: who may read it, write it, and (for
the trailer) rewrite the keys.

Each of the twelve bits is stored twice, once plain and once inverted. Silicon rejects
a trailer whose copies disagree, and a rejected trailer can leave a sector no key will
open again, so a mismatch raises here rather than decoding to a guess.

A leaf module, sibling of :mod:`keys`: pure wire format, shared by the Classic driver
and the in-memory tag image.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Iterable

__all__ = [
    "DEAD_DATA",
    "READ_ONLY_TRAILER",
    "TRANSPORT_DATA",
    "TRANSPORT_TRAILER",
    "AccessCondition",
    "data_permissions",
    "decode_access_bits",
    "encode_access_bits",
    "first_dead_data_block",
    "trailer_writers",
    "verify_redundancy",
]

#: One block's access condition: the bits ``(C1, C2, C3)``, each 0 or 1.
AccessCondition = tuple[int, int, int]

#: A data block anyone can read or write. What a blank sector ships with.
TRANSPORT_DATA: AccessCondition = (0, 0, 0)
#: A trailer key A can rewrite: the factory transport configuration.
TRANSPORT_TRAILER: AccessCondition = (0, 0, 1)
#: A trailer whose keys can never change again; access bits stay readable. What an
#: NDEF-formatted read-only sector uses.
READ_ONLY_TRAILER: AccessCondition = (0, 1, 1)
#: A data block no key can read or write. Inert; writing a trailer that puts a data
#: block here is refused.
DEAD_DATA: AccessCondition = (1, 1, 1)


def _nibble(bits: Iterable[int]) -> int:
    """Pack a bit per block into a nibble: blocks 0..3, block 3 as the high bit."""
    value = 0
    for block, bit in enumerate(bits):
        value |= (bit & 1) << block
    return value


def _check_condition(condition: AccessCondition) -> None:
    if len(condition) != 3 or any(bit not in (0, 1) for bit in condition):
        raise ValueError(f"an access condition is three bits, each 0 or 1: got {condition!r}")


def encode_access_bits(
    block0: AccessCondition,
    block1: AccessCondition,
    block2: AccessCondition,
    trailer: AccessCondition,
) -> bytes:
    """Encode the four blocks' conditions into the trailer's three access bytes.

    ``block0``..``block2`` are the data blocks; ``trailer`` is block 3. Each bit is
    carried both plain and inverted.

    >>> encode_access_bits((0, 0, 0), (0, 0, 0), (0, 0, 0), (0, 0, 1)).hex()
    'ff0780'
    >>> encode_access_bits((0, 0, 0), (0, 0, 0), (0, 0, 0), (0, 1, 1)).hex()
    '7f0788'
    """
    conditions = (block0, block1, block2, trailer)
    for condition in conditions:
        _check_condition(condition)
    c1 = _nibble(condition[0] for condition in conditions)
    c2 = _nibble(condition[1] for condition in conditions)
    c3 = _nibble(condition[2] for condition in conditions)

    def inv(nibble: int) -> int:
        return (~nibble) & 0xF

    byte6 = (inv(c2) << 4) | inv(c1)
    byte7 = (c1 << 4) | inv(c3)
    byte8 = (c3 << 4) | c2
    return bytes([byte6, byte7, byte8])


def verify_redundancy(access_bytes: bytes) -> None:
    """Raise unless the plain and inverted copies of every bit agree.

    The check the silicon makes. Run before every decode and every write.

    >>> verify_redundancy(bytes.fromhex("ff0780"))
    >>> verify_redundancy(bytes.fromhex("000000"))  # doctest: +ELLIPSIS
    Traceback (most recent call last):
    ValueError: access bits are inconsistent: ...
    """
    if len(access_bytes) != 3:
        raise ValueError(f"access bits are three bytes, got {len(access_bytes)}")
    byte6, byte7, byte8 = access_bytes
    c1 = byte7 >> 4
    c2 = byte8 & 0xF
    c3 = byte8 >> 4
    if (
        (byte6 & 0xF) != ((~c1) & 0xF)
        or (byte6 >> 4) != ((~c2) & 0xF)
        or (byte7 & 0xF) != ((~c3) & 0xF)
    ):
        raise ValueError(
            f"access bits are inconsistent: {access_bytes.hex()} has a bit that disagrees "
            "with its inverted copy, which silicon rejects"
        )


def decode_access_bits(
    access_bytes: bytes,
) -> tuple[AccessCondition, AccessCondition, AccessCondition, AccessCondition]:
    """Decode the three access bytes into the four blocks' conditions.

    Raises :class:`ValueError` via :func:`verify_redundancy` if the redundant copies
    disagree.

    >>> decode_access_bits(bytes.fromhex("ff0780"))
    ((0, 0, 0), (0, 0, 0), (0, 0, 0), (0, 0, 1))
    """
    verify_redundancy(access_bytes)
    _, byte7, byte8 = access_bytes
    c1 = byte7 >> 4
    c2 = byte8 & 0xF
    c3 = byte8 >> 4
    return tuple(  # type: ignore[return-value]
        ((c1 >> block) & 1, (c2 >> block) & 1, (c3 >> block) & 1) for block in range(4)
    )


#: Data-block read/write permission per condition, as sets of key letters.
#: NFC Forum / NXP MF1S50 access-conditions table, read/write columns only.
_DATA_PERMISSIONS: dict[AccessCondition, tuple[frozenset[str], frozenset[str]]] = {
    (0, 0, 0): (frozenset("AB"), frozenset("AB")),
    (0, 1, 0): (frozenset("AB"), frozenset()),
    (1, 0, 0): (frozenset("AB"), frozenset("B")),
    (1, 1, 0): (frozenset("AB"), frozenset("B")),
    (0, 0, 1): (frozenset("AB"), frozenset()),
    (0, 1, 1): (frozenset("B"), frozenset("B")),
    (1, 0, 1): (frozenset("B"), frozenset()),
    (1, 1, 1): (frozenset(), frozenset()),
}

#: Which keys may write the trailer block, per trailer condition. Empty means the
#: trailer is frozen.
_TRAILER_WRITERS: dict[AccessCondition, frozenset[str]] = {
    (0, 0, 0): frozenset("A"),
    (0, 1, 0): frozenset(),
    (1, 0, 0): frozenset("B"),
    (1, 1, 0): frozenset(),
    (0, 0, 1): frozenset("A"),
    (0, 1, 1): frozenset("B"),
    (1, 0, 1): frozenset(),
    (1, 1, 1): frozenset(),
}


def data_permissions(condition: AccessCondition) -> tuple[frozenset[str], frozenset[str]]:
    """The ``(readers, writers)`` key letters for a data block in this condition."""
    _check_condition(condition)
    return _DATA_PERMISSIONS[condition]


def trailer_writers(condition: AccessCondition) -> frozenset[str]:
    """The key letters that may rewrite a trailer in this condition; empty if frozen."""
    _check_condition(condition)
    return _TRAILER_WRITERS[condition]


def first_dead_data_block(
    conditions: tuple[AccessCondition, AccessCondition, AccessCondition, AccessCondition],
) -> int | None:
    """Index of the first data block no key could read or write, or ``None``.

    The trailer (index 3) is not checked: a frozen trailer is a legitimate read-only
    configuration, not a dead block.
    """
    for index, condition in enumerate(conditions[:3]):
        readers, writers = data_permissions(condition)
        if not readers and not writers:
            return index
    return None
