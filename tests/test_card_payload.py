"""The high-level tier: tag.write(...) and tag.read(), end to end over a fake tag."""

from __future__ import annotations

import pytest

from simple_nfc_tag.cards import identify
from simple_nfc_tag.codecs.values import U16
from simple_nfc_tag.exceptions import (
    CardFull,
    NdefNotSupported,
    UnknownFormat,
)
from simple_nfc_tag.readers.fake import (
    FakeClassic1K,
    FakeNTAG213,
    FakeNTAG216,
    FakeReader,
    FakeUltralight,
)


def tag_for(image=FakeNTAG213):
    reader = FakeReader(image())
    return identify(reader), reader


class TestRoundTrip:
    @pytest.mark.parametrize("image", [FakeUltralight, FakeNTAG213, FakeNTAG216, FakeClassic1K])
    def test_every_tag_type_round_trips(self, image):
        tag, _ = tag_for(image)
        tag.write(["ABC123", 42])
        assert tag.read() == ["ABC123", 42]

    def test_the_payload_lands_at_the_first_user_byte(self):
        image = FakeNTAG213()
        tag = identify(FakeReader(image))
        tag.write(["ABC123", U16(42)])
        # Page 4 is the first user page: the proprietary TLV starts exactly there.
        written = bytes(image.memory[16 : 16 + 15])
        assert written.hex(" ").upper() == "FD 0C 01 06 41 42 43 31 32 33 02 02 00 2A FE"

    def test_reading_costs_a_fraction_of_the_tag(self):
        # A 15-byte payload on an 888-byte NTAG216 must not read 888 bytes.
        tag, reader = tag_for(FakeNTAG216)
        tag.write(["ABC123", 42])
        before = len(reader.sent)
        assert tag.read() == ["ABC123", 42]
        assert len(reader.sent) - before <= 4

    def test_mixed_types(self):
        tag, _ = tag_for()
        values = ["text", 42, -7, True, False, 1.5, b"\x00\xff", {"k": [1, 2]}, None]
        tag.write(values)
        assert tag.read() == values

    def test_rewriting_a_shorter_payload(self):
        # The terminator, not the leftover bytes, decides where the payload ends.
        tag, _ = tag_for()
        tag.write(["a long first payload", 123456789])
        tag.write(["short"])
        assert tag.read() == ["short"]

    def test_a_bare_value_reads_back_as_a_one_element_list(self):
        tag, _ = tag_for()
        tag.write("hello")
        assert tag.read() == ["hello"]


class TestRawFormat:
    def test_round_trip(self):
        tag, _ = tag_for()
        tag.write(b"\x01\x02\x03\x04", format="raw")
        assert tag.read(format="raw")[:4] == b"\x01\x02\x03\x04"

    def test_raw_is_not_auto_detected(self):
        # Raw bytes carry nothing to recognise, so a formatless read must not guess.
        tag, _ = tag_for()
        tag.write(b"cf12ac\x00\x00", format="raw")
        with pytest.raises(UnknownFormat):
            tag.read()

    def test_reading_a_tag_written_by_the_original_script(self):
        # A fixed 16-byte layout, no framing.
        payload = b"cf12ac" + (42).to_bytes(2, "big") + bytes(range(8))
        tag, _ = tag_for()
        tag.write(payload, format="raw")

        read_back = tag.read(format="raw")
        assert read_back[:6] == b"cf12ac"
        assert int.from_bytes(read_back[6:8], "big") == 42
        assert read_back[8:16] == bytes(range(8))

    def test_a_tlv_tag_can_still_be_read_as_raw(self):
        tag, _ = tag_for()
        tag.write(["x"])
        assert tag.read(format="raw")[0] == 0xFD


class TestCapacity:
    def test_a_payload_that_does_not_fit_is_refused(self):
        tag, _ = tag_for(FakeUltralight)  # 48 bytes
        with pytest.raises(CardFull) as excinfo:
            tag.write(["x" * 60])
        assert excinfo.value.available == 48

    def test_nothing_is_written_when_the_payload_does_not_fit(self):
        # A half-written payload would destroy what was there.
        image = FakeUltralight()
        tag = identify(FakeReader(image))
        tag.write(["keep me"])
        before = bytes(image.memory)

        with pytest.raises(CardFull):
            tag.write(["x" * 60])

        assert bytes(image.memory) == before
        assert tag.read() == ["keep me"]

    def test_filling_a_tag_to_the_byte(self):
        tag, _ = tag_for(FakeUltralight)
        # 48 bytes total: FD + length + FE is 3, and a str needs 2 more for T and L.
        tag.write(["x" * 43])
        assert tag.read() == ["x" * 43]


class TestFormatDispatch:
    def test_a_blank_tag_says_so(self):
        tag, _ = tag_for()
        with pytest.raises(UnknownFormat, match="format='raw'"):
            tag.read()

    def test_an_ndef_tag_is_named_not_mangled(self):
        image = FakeNTAG213()
        # A minimal NDEF TLV where the payload would be.
        image.memory[16:22] = bytes([0x03, 0x03, 0xD0, 0x00, 0x00, 0xFE])
        tag = identify(FakeReader(image))
        with pytest.raises(NdefNotSupported, match="format='raw'"):
            tag.read()

    def test_an_unknown_format_names_the_available_ones(self):
        tag, _ = tag_for()
        with pytest.raises(UnknownFormat, match="'tlv'"):
            tag.read(format="ndef")

    def test_writing_with_an_unknown_format(self):
        tag, _ = tag_for()
        with pytest.raises(UnknownFormat):
            tag.write(["x"], format="ndef")


class TestClassicIntegration:
    def test_a_payload_spanning_a_sector_trailer(self):
        image = FakeClassic1K()
        tag = identify(FakeReader(image))
        values = ["a payload long enough to cross a trailer", 1234, True]
        tag.write(values)
        assert tag.read() == values
        assert 7 not in image.writes

    def test_the_trailer_keys_survive(self):
        image = FakeClassic1K()
        tag = identify(FakeReader(image))
        tag.write(["x" * 60])
        trailer = bytes(image.memory[7 * 16 : 8 * 16])
        assert trailer[:6] == b"\xff\xff\xff\xff\xff\xff"
