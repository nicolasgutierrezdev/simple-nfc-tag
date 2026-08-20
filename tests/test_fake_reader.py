"""The in-memory reader.

These test the tag images: the fake has to fail where silicon fails, or every test
built on it means nothing. The behaviours pinned here were captured from an ACR122U
with an NTAG213 on it.
"""

from __future__ import annotations

import pytest

from simple_nfc_tag.exceptions import ApduError, NoCardPresent, ReaderNotSupported
from simple_nfc_tag.keys import FACTORY_KEY, KeyType
from simple_nfc_tag.readers.fake import (
    FakeClassic1K,
    FakeNTAG213,
    FakeNTAG215,
    FakeNTAG216,
    FakeReader,
    FakeUltralight,
)


class TestPresence:
    def test_empty_field(self):
        reader = FakeReader()
        assert not reader.open_card_connection()
        with pytest.raises(NoCardPresent):
            reader.get_uid()

    def test_uid_comes_back(self):
        tag = FakeNTAG213()
        reader = FakeReader(tag)
        assert reader.get_uid() == tag.uid

    def test_presenting_a_tag_drops_the_previous_connection(self):
        reader = FakeReader(FakeNTAG213())
        reader.get_uid()
        assert reader.has_card_connection

        reader.present(FakeUltralight(uid=b"\x04\x00\x00\x00\x00\x00\x01"))
        assert not reader.has_card_connection
        assert reader.get_uid().endswith(b"\x01")

    def test_removal_empties_the_field(self):
        reader = FakeReader(FakeNTAG213())
        reader.get_uid()
        reader.remove()
        assert not reader.open_card_connection()

    def test_connections_are_counted(self):
        reader = FakeReader(FakeNTAG213())
        reader.get_uid()
        reader.get_uid()
        assert reader.connections_opened == 1


class TestUltralightImage:
    def test_atr_reports_the_ultralight_card_name(self):
        reader = FakeReader(FakeNTAG213())
        # 0003 sits at the same offset a real reader puts it.
        assert reader.get_atr()[13:15] == b"\x00\x03"

    def test_a_read_returns_four_pages(self):
        reader = FakeReader(FakeNTAG213())
        assert len(reader.read_binary(4, 16)) == 16

    def test_reading_the_last_page_wraps_around_to_page_zero(self):
        # Real NTAG213 behaviour: reading page 44 returns 44 then 0, 1, 2.
        tag = FakeNTAG213()
        reader = FakeReader(tag)
        data = reader.read_binary(44, 16)
        assert data[4:16] == bytes(tag.memory[0:12])

    def test_reading_past_the_end_answers_6300_not_6a82(self):
        reader = FakeReader(FakeNTAG213())
        with pytest.raises(ApduError) as excinfo:
            reader.read_binary(45, 4)
        assert excinfo.value.status_word == 0x6300

    def test_the_uid_pages_are_read_only(self):
        reader = FakeReader(FakeNTAG213())
        with pytest.raises(ApduError):
            reader.update_binary(0, b"\x00\x00\x00\x00")

    def test_user_pages_round_trip(self):
        reader = FakeReader(FakeNTAG213())
        reader.update_binary(7, b"ABCD")
        assert reader.read_binary(7, 4) == b"ABCD"

    def test_writes_are_recorded(self):
        tag = FakeNTAG213()
        reader = FakeReader(tag)
        reader.update_binary(5, b"WXYZ")
        assert tag.writes == [5]

    @pytest.mark.parametrize(
        ("image", "storage"),
        [(FakeNTAG213, 0x0F), (FakeNTAG215, 0x11), (FakeNTAG216, 0x13)],
    )
    def test_get_version_reports_the_storage_size(self, image, storage):
        reader = FakeReader(image())
        assert reader.transceive(b"\x60")[6] == storage

    def test_a_plain_ultralight_has_no_get_version(self):
        # Which is why identification needs a fallback.
        reader = FakeReader(FakeUltralight())
        with pytest.raises(ApduError):
            reader.transceive(b"\x60")

    def test_a_reader_without_passthrough_says_so(self):
        reader = FakeReader(FakeNTAG213(), supports_transceive=False)
        with pytest.raises(ReaderNotSupported):
            reader.transceive(b"\x60")


class TestClassicImage:
    def test_a_sector_cannot_be_read_before_authentication(self):
        # Measured on hardware: 63 00, not the 69 82 that "security status not
        # satisfied" would suggest.
        reader = FakeReader(FakeClassic1K())
        with pytest.raises(ApduError) as excinfo:
            reader.read_binary(4, 16)
        assert excinfo.value.status_word == 0x6300

    def test_the_factory_key_opens_a_sector(self):
        reader = FakeReader(FakeClassic1K())
        reader.load_key(0, FACTORY_KEY)
        reader.authenticate(4, KeyType.A, 0)
        assert len(reader.read_binary(4, 16)) == 16

    def test_the_wrong_key_is_refused(self):
        reader = FakeReader(FakeClassic1K(key_a=b"\x01" * 6))
        reader.load_key(0, FACTORY_KEY)
        with pytest.raises(ApduError):
            reader.authenticate(4, KeyType.A, 0)

    def test_key_b_is_checked_against_key_b(self):
        reader = FakeReader(FakeClassic1K(key_a=b"\x01" * 6, key_b=b"\x02" * 6))
        reader.load_key(0, b"\x02" * 6)
        reader.authenticate(4, KeyType.B, 0)
        assert reader.read_binary(4, 16) is not None

    def test_authenticating_one_sector_does_not_open_another(self):
        reader = FakeReader(FakeClassic1K())
        reader.load_key(0, FACTORY_KEY)
        reader.authenticate(4, KeyType.A, 0)
        with pytest.raises(ApduError):
            reader.read_binary(8, 16)

    def test_opening_a_sector_closes_the_previous_one(self):
        # Only one sector is authenticated at a time.
        reader = FakeReader(FakeClassic1K())
        reader.load_key(0, FACTORY_KEY)
        reader.authenticate(4, KeyType.A, 0)
        reader.read_binary(4, 16)

        reader.authenticate(8, KeyType.A, 0)
        with pytest.raises(ApduError):
            reader.read_binary(4, 16)

        reader.authenticate(4, KeyType.A, 0)
        assert len(reader.read_binary(4, 16)) == 16

    def test_a_failed_authentication_closes_the_open_sector_too(self):
        reader = FakeReader(FakeClassic1K())
        reader.load_key(0, FACTORY_KEY)
        reader.authenticate(4, KeyType.A, 0)

        reader.load_key(0, bytes([0xDE]) * 6)
        with pytest.raises(ApduError):
            reader.authenticate(8, KeyType.A, 0)
        with pytest.raises(ApduError):
            reader.read_binary(4, 16)

    def test_key_a_reads_back_as_zeros(self):
        # Measured on hardware: key A is never readable, whatever the access bits say.
        # The access bits and key B come back as stored.
        tag = FakeClassic1K()
        reader = FakeReader(tag)
        reader.load_key(0, FACTORY_KEY)
        reader.authenticate(4, KeyType.A, 0)

        trailer = reader.read_binary(7, 16)
        assert trailer[:6] == bytes(6)
        assert trailer[6:10] == bytes([0xFF, 0x07, 0x80, 0x69])
        assert trailer[10:] == FACTORY_KEY
        # The key is still there; it does not come back over the air.
        assert bytes(tag.memory[7 * 16 : 7 * 16 + 6]) == FACTORY_KEY


class TestUnmodelledCommands:
    def test_an_unknown_apdu_is_refused_rather_than_silently_accepted(self):
        reader = FakeReader(FakeNTAG213())
        data, sw1, sw2 = reader.transmit_raw(b"\xff\x99\x00\x00\x00")
        assert (sw1, sw2) == (0x6D, 0x00)
        assert data == b""


class TestSessionPoisoning:
    """A refused command deselects the tag, exactly as real silicon does."""

    def test_a_refusal_stops_the_tag_answering_anything(self):
        reader = FakeReader(FakeNTAG213())
        with pytest.raises(ApduError):
            reader.read_binary(45, 4)  # past the end

        with pytest.raises(ApduError) as excinfo:
            reader.read_binary(4, 16)  # a page that plainly exists
        assert excinfo.value.status_word == 0x6300

    def test_resetting_the_session_makes_the_tag_answer_again(self):
        reader = FakeReader(FakeNTAG213())
        with pytest.raises(ApduError):
            reader.read_binary(45, 4)

        assert reader.reset_card_connection()
        assert len(reader.read_binary(4, 16)) == 16
        assert reader.resets == 1

    def test_a_reset_with_no_tag_reports_failure(self):
        reader = FakeReader(FakeNTAG213())
        reader.get_uid()
        reader.tag = None
        assert reader.reset_card_connection() is False

    def test_a_refused_key_does_not_deselect_the_tag(self):
        # Unlike an out-of-range NTAG read, a wrong Classic key leaves the tag
        # listening: the next attempt works with no session reset in between.
        real_key = bytes([0x01]) * 6
        reader = FakeReader(FakeClassic1K(key_a=real_key, key_b=real_key))
        reader.load_key(0, FACTORY_KEY)
        with pytest.raises(ApduError):
            reader.authenticate(4, KeyType.A, 0)

        reader.load_key(0, real_key)
        reader.authenticate(4, KeyType.A, 0)
        assert len(reader.read_binary(4, 16)) == 16
        assert reader.resets == 0
