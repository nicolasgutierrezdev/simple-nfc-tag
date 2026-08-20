"""The Card linear tier: flat offsets over a block layout with holes in it."""

from __future__ import annotations

import pytest

from simple_nfc_tag.exceptions import CardFull
from support import MemoryCard

# MemoryCard's default layout: user blocks 4, 5, 6, 8. Block 7 stands in for a sector
# trailer, so linear offset 12 lands on block 8.


class TestReadBytes:
    def test_reads_within_one_block(self):
        card = MemoryCard()
        card.blocks[4] = b"ABCD"
        assert card.read_bytes(1, 2) == b"BC"

    def test_reads_across_a_block_boundary(self):
        card = MemoryCard()
        card.blocks[4] = b"ABCD"
        card.blocks[5] = b"EFGH"
        assert card.read_bytes(2, 4) == b"CDEF"

    def test_skips_the_hole_in_the_layout(self):
        card = MemoryCard()
        card.blocks[6] = b"IJKL"
        card.blocks[8] = b"MNOP"
        assert card.read_bytes(8, 8) == b"IJKLMNOP"
        assert 7 not in card.reads

    def test_only_touches_the_blocks_it_needs(self):
        card = MemoryCard()
        card.read_bytes(4, 4)
        assert card.reads == [5]

    def test_zero_length_reads_nothing_at_all(self):
        card = MemoryCard()
        assert card.read_bytes(0, 0) == b""
        assert card.reads == []

    def test_reading_past_the_end_raises_card_full(self):
        card = MemoryCard()
        with pytest.raises(CardFull) as excinfo:
            card.read_bytes(14, 4)
        assert excinfo.value.available == 16

    def test_reading_the_last_byte_is_allowed(self):
        card = MemoryCard()
        card.blocks[8] = b"WXYZ"
        assert card.read_bytes(15, 1) == b"Z"

    @pytest.mark.parametrize(("offset", "length"), [(-1, 4), (0, -1)])
    def test_negative_arguments_are_programming_errors(self, offset, length):
        with pytest.raises(ValueError, match="negative"):
            MemoryCard().read_bytes(offset, length)


class TestWriteBytes:
    def test_writes_a_whole_block_without_reading_it_first(self):
        card = MemoryCard()
        # verify= off: this is about the read-modify-write economy, and a
        # verifying read-back would count towards card.reads.
        card.write_bytes(0, b"ABCD", verify=False)
        assert card.blocks[4] == b"ABCD"
        assert card.reads == []

    def test_partial_write_preserves_the_rest_of_the_block(self):
        # The read-modify-write an Ultralight needs for anything not page-aligned.
        card = MemoryCard()
        card.blocks[4] = b"ABCD"
        card.write_bytes(1, b"xy", verify=False)
        assert card.blocks[4] == b"AxyD"
        assert card.reads == [4]

    def test_write_spanning_blocks_merges_only_the_partial_ends(self):
        card = MemoryCard()
        card.blocks[4] = b"ABCD"
        card.blocks[5] = b"EFGH"
        card.blocks[6] = b"IJKL"
        card.write_bytes(3, b"123456", verify=False)
        assert card.blocks[4] == b"ABC1"
        assert card.blocks[5] == b"2345"
        assert card.blocks[6] == b"6JKL"
        # Only the two partial blocks were read back; the full one was not.
        assert card.reads == [4, 6]

    def test_write_lands_across_the_hole(self):
        card = MemoryCard()
        card.write_bytes(8, b"IJKLMNOP")
        assert card.blocks[6] == b"IJKL"
        assert card.blocks[8] == b"MNOP"
        assert 7 not in card.writes

    def test_writing_past_the_end_raises_before_touching_the_tag(self):
        card = MemoryCard()
        with pytest.raises(CardFull) as excinfo:
            card.write_bytes(12, b"12345")
        assert (excinfo.value.needed, excinfo.value.available) == (17, 16)
        assert card.writes == []

    def test_filling_the_tag_exactly_is_allowed(self):
        card = MemoryCard()
        card.write_bytes(0, bytes(range(16)))
        assert card.read_bytes(0, 16) == bytes(range(16))

    def test_empty_write_is_a_no_op(self):
        card = MemoryCard()
        card.write_bytes(0, b"")
        assert card.writes == []


class TestGeometry:
    def test_user_size_counts_only_user_blocks(self):
        assert MemoryCard().user_size == 16
        assert MemoryCard(user_blocks=(4, 5)).user_size == 8

    def test_repr_names_the_product_and_uid(self):
        card = MemoryCard(uid=b"\x04\x01\x02\x03")
        assert "MemoryCard" in repr(card)
        assert "04010203" in repr(card)

    def test_round_trip_through_the_linear_tier(self):
        card = MemoryCard()
        payload = b"the quick brown!"
        card.write_bytes(0, payload)
        assert card.read_bytes(0, len(payload)) == payload
