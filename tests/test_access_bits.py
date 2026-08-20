"""The MIFARE Classic access-bit codec.

Pure-function tests, no reader and no tag. A single wrong bit locks a sector forever,
so the encoding is pinned exhaustively and against the bytes real tags carry.
"""

from __future__ import annotations

import itertools

import pytest

from simple_nfc_tag import access_bits
from simple_nfc_tag.access_bits import (
    DEAD_DATA,
    READ_ONLY_TRAILER,
    TRANSPORT_DATA,
    TRANSPORT_TRAILER,
    decode_access_bits,
    encode_access_bits,
    first_dead_data_block,
    verify_redundancy,
)

ALL_CONDITIONS = list(itertools.product((0, 1), repeat=3))


class TestKnownHardwareValues:
    def test_transport_configuration(self):
        # FF 07 80 is what a blank sector ships with: open data, key A owns the trailer.
        encoded = encode_access_bits(
            TRANSPORT_DATA, TRANSPORT_DATA, TRANSPORT_DATA, TRANSPORT_TRAILER
        )
        assert encoded.hex() == "ff0780"

    def test_ndef_read_only_trailer(self):
        # 7F 07 88 is what the NDEF sectors on the reference tag carry: open data, but a
        # trailer whose keys can never change again.
        encoded = encode_access_bits(
            TRANSPORT_DATA, TRANSPORT_DATA, TRANSPORT_DATA, READ_ONLY_TRAILER
        )
        assert encoded.hex() == "7f0788"

    def test_transport_decodes_back(self):
        assert decode_access_bits(bytes.fromhex("ff0780")) == (
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 1),
        )


class TestRoundTrip:
    # All 8**4 combinations, swept in-test rather than parametrized: 4096 ids per sweep
    # bought nothing over one id that names the failing combination.
    def test_every_combination_round_trips(self):
        for blocks in itertools.product(ALL_CONDITIONS, repeat=4):
            assert decode_access_bits(encode_access_bits(*blocks)) == blocks, blocks

    def test_every_encoding_passes_its_own_redundancy(self):
        for blocks in itertools.product(ALL_CONDITIONS, repeat=4):
            encoded = encode_access_bits(*blocks)
            try:
                verify_redundancy(encoded)
            except ValueError as exc:  # pragma: no cover - a regression in the encoder
                pytest.fail(f"{blocks} encoded to {encoded.hex()}: {exc}")


class TestRedundancy:
    def test_all_zeros_is_rejected(self):
        # 00 00 00 has every inverted copy wrong; silicon rejects it, so decoding must
        # too rather than returning a plausible-looking condition.
        with pytest.raises(ValueError, match="inconsistent"):
            verify_redundancy(bytes.fromhex("000000"))

    def test_decode_refuses_an_inconsistent_trailer(self):
        with pytest.raises(ValueError, match="inconsistent"):
            decode_access_bits(bytes.fromhex("ffffff"))

    def test_wrong_length_is_rejected(self):
        with pytest.raises(ValueError, match="three bytes"):
            verify_redundancy(bytes.fromhex("ff07"))

    def test_a_single_flipped_bit_is_caught(self):
        good = bytearray(encode_access_bits(*([TRANSPORT_DATA] * 3), TRANSPORT_TRAILER))
        good[0] ^= 0x01
        with pytest.raises(ValueError, match="inconsistent"):
            verify_redundancy(bytes(good))


class TestValidation:
    def test_a_condition_must_be_three_bits(self):
        with pytest.raises(ValueError, match="three bits"):
            encode_access_bits(TRANSPORT_DATA, TRANSPORT_DATA, TRANSPORT_DATA, (0, 1))

    def test_bits_must_be_zero_or_one(self):
        with pytest.raises(ValueError, match="0 or 1"):
            encode_access_bits(TRANSPORT_DATA, TRANSPORT_DATA, TRANSPORT_DATA, (0, 2, 0))


class TestDeadBlockDetection:
    def test_transport_has_no_dead_block(self):
        conditions = (TRANSPORT_DATA, TRANSPORT_DATA, TRANSPORT_DATA, TRANSPORT_TRAILER)
        assert first_dead_data_block(conditions) is None

    def test_a_read_never_write_never_data_block_is_dead(self):
        assert (
            first_dead_data_block((TRANSPORT_DATA, DEAD_DATA, TRANSPORT_DATA, TRANSPORT_TRAILER))
            == 1
        )

    def test_a_frozen_trailer_is_not_a_dead_block(self):
        # A read-only trailer is a legitimate configuration; only data blocks count.
        assert (
            first_dead_data_block((TRANSPORT_DATA, TRANSPORT_DATA, TRANSPORT_DATA, DEAD_DATA))
            is None
        )


class TestPermissions:
    def test_transport_data_is_open_to_both_keys(self):
        readers, writers = access_bits.data_permissions(TRANSPORT_DATA)
        assert readers == frozenset("AB")
        assert writers == frozenset("AB")

    def test_a_dead_data_block_admits_no_key(self):
        readers, writers = access_bits.data_permissions(DEAD_DATA)
        assert not readers
        assert not writers

    def test_key_a_owns_a_transport_trailer(self):
        assert access_bits.trailer_writers(TRANSPORT_TRAILER) == frozenset("A")

    def test_a_read_only_trailer_is_frozen_to_key_a(self):
        # 011: only key B could rewrite it, and on an NDEF tag key B is unknown, so the
        # sector's keys are effectively permanent.
        assert access_bits.trailer_writers(READ_ONLY_TRAILER) == frozenset("B")
