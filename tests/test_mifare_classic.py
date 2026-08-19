"""The MIFARE Classic driver: sector geometry, trailer safety, authentication."""

from __future__ import annotations

import pytest

from simple_nfc_tag.cards import identify
from simple_nfc_tag.cards.mifare_classic import Classic1K, Classic4K, MifareClassic
from simple_nfc_tag.exceptions import AuthenticationError, CardFull
from simple_nfc_tag.keys import FACTORY_KEY, KeyType, StaticKeyProvider
from simple_nfc_tag.readers.fake import FakeClassic1K, FakeClassic4K, FakeReader

CUSTOM_KEY = bytes.fromhex("A0A1A2A3A4A5")


def card_for(image=FakeClassic1K, **image_kwargs):
    reader = FakeReader(image(**image_kwargs))
    return identify(reader), reader


def auths(reader):
    """The authenticate APDUs a reader was sent."""
    return [apdu for apdu in reader.sent if apdu[:2] == bytes([0xFF, 0x86])]


class TestIdentification:
    def test_card_name_0001_is_a_1k(self):
        card, _ = card_for(FakeClassic1K)
        assert type(card) is Classic1K

    def test_card_name_0002_is_a_4k(self):
        card, _ = card_for(FakeClassic4K)
        assert type(card) is Classic4K


class TestGeometry:
    def test_1k_user_size(self):
        # 15 usable sectors of three data blocks: sector 0 is skipped whole.
        card, _ = card_for(FakeClassic1K)
        assert card.user_size == 720

    def test_4k_user_size(self):
        card, _ = card_for(FakeClassic4K)
        assert card.user_size == 3408

    def test_user_memory_starts_at_block_four(self):
        card, _ = card_for()
        assert card._user_blocks()[0] == 4

    def test_no_trailer_is_ever_user_memory(self):
        card, _ = card_for(FakeClassic4K)
        assert not any(MifareClassic.is_trailer(block) for block in card._user_blocks())

    def test_block_zero_is_never_user_memory(self):
        card, _ = card_for()
        assert 0 not in card._user_blocks()

    @pytest.mark.parametrize(("block", "sector"), [(0, 0), (3, 0), (4, 1), (63, 15)])
    def test_small_sector_mapping(self, block, sector):
        assert MifareClassic.sector_of(block) == sector

    @pytest.mark.parametrize(("block", "sector"), [(127, 31), (128, 32), (143, 32), (144, 33)])
    def test_4k_switches_to_sixteen_block_sectors(self, block, sector):
        assert MifareClassic.sector_of(block) == sector

    @pytest.mark.parametrize("block", [3, 7, 63, 143, 255])
    def test_trailers_are_recognised_in_both_sector_sizes(self, block):
        assert MifareClassic.is_trailer(block)

    def test_linear_offsets_skip_the_trailer(self):
        # Offset 48 is the fourth block of the run, which is block 8 -- not block 7,
        # which holds the keys.
        card, _ = card_for()
        assert card._user_blocks()[3] == 8


class TestAuthentication:
    def test_a_sector_is_authenticated_once_while_it_stays_open(self):
        card, reader = card_for()
        card.read_bytes(0, 16)
        card.read_bytes(16, 16)
        card.read_bytes(32, 16)

        assert len(auths(reader)) == 1
        assert card.authenticated_sector == 1

    def test_crossing_into_the_next_sector_authenticates_again(self):
        card, reader = card_for()
        card.read_bytes(0, 48)  # sector 1
        card.read_bytes(48, 16)  # sector 2
        assert len(auths(reader)) == 2
        assert card.authenticated_sector == 2

    def test_going_back_to_an_earlier_sector_reauthenticates(self):
        # Only one sector is open at a time, so returning to sector 1 costs another
        # authentication. Believing it was still open would read 63 00 forever.
        card, reader = card_for()
        card.read_bytes(0, 16)  # sector 1
        card.read_bytes(48, 16)  # sector 2 -- closes sector 1
        card.read_bytes(0, 16)  # sector 1 again
        assert len(auths(reader)) == 3
        assert card.authenticated_sector == 1

    def test_a_read_spanning_two_sectors(self):
        image = FakeClassic1K()
        card = identify(FakeReader(image))
        payload = bytes(range(64))
        card.write_bytes(0, payload)
        assert card.read_bytes(0, 64) == payload

    def test_the_factory_key_is_tried_first(self):
        card, reader = card_for()
        card.read_bytes(0, 4)
        loads = [apdu for apdu in reader.sent if apdu[:2] == b"\xff\x82"]
        assert loads[0][5:] == FACTORY_KEY

    def test_a_second_candidate_is_tried_when_the_first_is_refused(self):
        image = FakeClassic1K(key_a=CUSTOM_KEY, key_b=CUSTOM_KEY)
        image.memory[4 * 16 : 4 * 16 + 4] = b"DATA"
        reader = FakeReader(image)
        card = identify(reader)

        assert card.read_bytes(0, 4) == b"DATA"
        loads = [apdu[5:] for apdu in reader.sent if apdu[:2] == b"\xff\x82"]
        assert loads[0] == FACTORY_KEY
        assert CUSTOM_KEY in loads
        # A refused key does not deselect a Classic, so no session reset is needed.
        assert reader.resets == 0

    def test_a_refused_key_leaves_no_sector_claimed_as_open(self):
        # An authentication attempt closes the open sector whether it succeeds or not,
        # so a failure must not leave the previous sector cached as usable.
        card, _ = card_for(key_a=CUSTOM_KEY, key_b=CUSTOM_KEY)
        card.keys = StaticKeyProvider(key=bytes([0x99]) * 6, key_type=KeyType.A)
        with pytest.raises(AuthenticationError):
            card.read_bytes(0, 4)
        assert card.authenticated_sector is None

    def test_no_key_works_and_the_error_says_how_many_were_tried(self):
        card, _ = card_for(key_a=b"\x11" * 6, key_b=b"\x22" * 6)
        with pytest.raises(AuthenticationError) as excinfo:
            card.read_bytes(0, 4)
        assert "sector 1" in str(excinfo.value)
        assert "candidate" in str(excinfo.value)

    def test_a_supplied_key_is_used(self):
        card, reader = card_for(key_a=CUSTOM_KEY, key_b=CUSTOM_KEY)
        card.keys = StaticKeyProvider(key=CUSTOM_KEY, key_type=KeyType.A)
        card.read_bytes(0, 4)
        loads = [apdu[5:] for apdu in reader.sent if apdu[:2] == b"\xff\x82"]
        assert loads == [CUSTOM_KEY]

    def test_changing_the_key_policy_closes_the_open_sector(self):
        card, _ = card_for()
        card.read_bytes(0, 4)
        assert card.authenticated_sector == 1

        card.keys = StaticKeyProvider(key=FACTORY_KEY)
        assert card.authenticated_sector is None


class TestReadWrite:
    def test_round_trip(self):
        card, _ = card_for()
        card.write_bytes(0, b"a classic payload")
        assert card.read_bytes(0, 17) == b"a classic payload"

    def test_a_write_spanning_a_trailer_lands_correctly(self):
        image = FakeClassic1K()
        card = identify(FakeReader(image))
        payload = bytes(range(48))
        card.write_bytes(0, payload)
        assert card.read_bytes(0, 48) == payload
        assert image.writes == [4, 5, 6]
        assert 7 not in image.writes

    def test_a_write_across_the_sector_boundary(self):
        image = FakeClassic1K()
        card = identify(FakeReader(image))
        payload = bytes(range(64))
        card.write_bytes(0, payload)
        assert card.read_bytes(0, 64) == payload
        assert image.writes == [4, 5, 6, 8]

    def test_writing_a_trailer_directly_is_refused(self):
        card, _ = card_for()
        with pytest.raises(ValueError, match="sector trailer"):
            card.write_block(7, bytes(16))

    def test_the_trailer_still_holds_its_keys_after_a_spanning_write(self):
        image = FakeClassic1K()
        card = identify(FakeReader(image))
        card.write_bytes(0, bytes(range(48)))
        trailer = bytes(image.memory[7 * 16 : 8 * 16])
        assert trailer[:6] == FACTORY_KEY
        assert trailer[10:] == FACTORY_KEY

    def test_filling_the_tag_exactly(self):
        card, _ = card_for()
        payload = bytes(range(256)) * 2 + bytes(208)
        card.write_bytes(0, payload)
        assert card.read_bytes(0, 720) == payload

    def test_one_byte_too_many(self):
        card, _ = card_for()
        with pytest.raises(CardFull) as excinfo:
            card.write_bytes(0, bytes(721))
        assert excinfo.value.available == 720

    def test_block_writes_must_be_a_whole_block(self):
        card, _ = card_for()
        with pytest.raises(ValueError, match="16 bytes"):
            card.write_block(4, b"short")
