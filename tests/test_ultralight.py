"""The Ultralight / NTAG21x driver: identification, geometry, page arithmetic."""

from __future__ import annotations

import pytest

from simple_nfc_tag.cards import identify
from simple_nfc_tag.cards.ultralight import NTAG213, NTAG215, NTAG216, Ultralight
from simple_nfc_tag.exceptions import CardFull
from simple_nfc_tag.readers.fake import (
    FakeNTAG213,
    FakeNTAG215,
    FakeNTAG216,
    FakeReader,
    FakeUltralight,
)


def card_for(image, **reader_kwargs):
    return identify(FakeReader(image(), **reader_kwargs))


class TestIdentification:
    @pytest.mark.parametrize(
        ("image", "driver"),
        [
            (FakeNTAG213, NTAG213),
            (FakeNTAG215, NTAG215),
            (FakeNTAG216, NTAG216),
        ],
    )
    def test_get_version_pins_the_exact_product(self, image, driver):
        assert type(card_for(image)) is driver

    @pytest.mark.parametrize(
        ("image", "driver"),
        [
            (FakeUltralight, Ultralight),
            (FakeNTAG213, NTAG213),
            (FakeNTAG215, NTAG215),
            (FakeNTAG216, NTAG216),
        ],
    )
    def test_probing_finds_the_same_product_without_a_passthrough(self, image, driver):
        # A reader with no raw passthrough cannot ask GET_VERSION, so the driver finds
        # the end of memory by probing. Same answer either way.
        assert type(card_for(image, supports_transceive=False)) is driver

    def test_a_plain_ultralight_is_identified_despite_having_no_get_version(self):
        assert type(card_for(FakeUltralight)) is Ultralight

    def test_the_tag_is_still_readable_after_probing_identification(self):
        # Probing reads past the end of memory, which deselects the tag. Without a
        # session reset the tag identifies correctly and then refuses every read that
        # follows, as measured on hardware.
        image = FakeNTAG213()
        image.memory[16:20] = b"DATA"
        card = identify(FakeReader(image, supports_transceive=False))
        assert card.read_bytes(0, 4) == b"DATA"

    def test_a_plain_ultralight_is_readable_after_a_refused_get_version(self):
        image = FakeUltralight()
        image.memory[16:20] = b"DATA"
        card = identify(FakeReader(image))
        assert card.read_bytes(0, 4) == b"DATA"

    def test_identification_costs_one_command_when_the_reader_can_ask(self):
        reader = FakeReader(FakeNTAG213())
        identify(reader)
        # ATR, UID, GET_VERSION, and no page probing.
        assert len(reader.sent) == 1  # only the UID; GET_VERSION goes via transceive

    def test_uid_is_carried_onto_the_card(self):
        image = FakeNTAG213()
        card = identify(FakeReader(image))
        assert card.uid == image.uid


class TestGeometry:
    @pytest.mark.parametrize(
        ("image", "user_size"),
        [
            (FakeUltralight, 48),
            (FakeNTAG213, 144),
            (FakeNTAG215, 504),
            (FakeNTAG216, 888),
        ],
    )
    def test_user_size_matches_the_datasheet(self, image, user_size):
        assert card_for(image).user_size == user_size

    def test_user_memory_starts_at_page_four(self):
        card = card_for(FakeNTAG213)
        assert next(iter(card._user_blocks())) == 4

    def test_user_memory_stops_before_the_config_pages(self):
        # NTAG213 has 45 pages; the last four hold the password and mirror config.
        card = card_for(FakeNTAG213)
        assert list(card._user_blocks())[-1] == 39


class TestReadWrite:
    def test_round_trip_through_user_memory(self):
        card = card_for(FakeNTAG213)
        card.write_bytes(0, b"hello tag")
        assert card.read_bytes(0, 9) == b"hello tag"

    def test_writes_land_on_the_right_pages(self):
        image = FakeNTAG213()
        card = identify(FakeReader(image))
        card.write_bytes(0, b"ABCDEFGH")
        assert image.writes == [4, 5]
        assert bytes(image.memory[16:24]) == b"ABCDEFGH"

    def test_unaligned_write_reads_the_page_back_first(self):
        image = FakeNTAG213()
        card = identify(FakeReader(image))
        card.write_bytes(0, b"ABCD")
        card.write_bytes(1, b"xy")
        assert card.read_bytes(0, 4) == b"AxyD"

    def test_a_read_batches_four_pages_per_command(self):
        image = FakeNTAG213()
        reader = FakeReader(image)
        card = identify(reader)
        before = len(reader.sent)
        card.read_bytes(0, 16)
        # One APDU for 16 bytes, not four.
        assert len(reader.sent) - before == 1

    def test_a_long_read_uses_one_command_per_four_pages(self):
        image = FakeNTAG213()
        reader = FakeReader(image)
        card = identify(reader)
        before = len(reader.sent)
        card.read_bytes(0, 64)
        assert len(reader.sent) - before == 4

    def test_filling_an_ultralight_exactly(self):
        card = card_for(FakeUltralight)
        payload = bytes(range(48))
        card.write_bytes(0, payload)
        assert card.read_bytes(0, 48) == payload

    def test_one_byte_too_many_for_an_ultralight(self):
        card = card_for(FakeUltralight)
        with pytest.raises(CardFull) as excinfo:
            card.write_bytes(0, bytes(49))
        assert (excinfo.value.needed, excinfo.value.available) == (49, 48)

    def test_a_write_never_reaches_the_config_pages(self):
        image = FakeNTAG213()
        card = identify(FakeReader(image))
        with pytest.raises(CardFull):
            card.write_bytes(140, b"12345")
        assert image.writes == []

    def test_block_writes_must_be_a_whole_page(self):
        card = card_for(FakeNTAG213)
        with pytest.raises(ValueError, match="4 bytes"):
            card.write_block(4, b"ABC")
