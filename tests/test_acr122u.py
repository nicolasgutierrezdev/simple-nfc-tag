"""The ACR122U driver: PN532 passthrough and vendor peripherals.

The GET_VERSION exchange below is a real one, captured from an ACR122U with an
NTAG213 on it.
"""

from __future__ import annotations

import pytest

from simple_nfc_tag.exceptions import ApduError, ReaderError
from support import StubACR122U, pn532_reply

#: What an NTAG213 answers GET_VERSION with. Storage byte 0x0F is what makes it a 213.
NTAG213_VERSION = bytes.fromhex("0004040201000F03")


class TestTransceive:
    def test_wraps_the_payload_for_the_pn532(self):
        reader = StubACR122U([pn532_reply(NTAG213_VERSION)])
        assert reader.transceive(b"\x60") == NTAG213_VERSION
        # FF 00 00 00 <Lc> D4 42 <payload>, Lc counting the D4 42 header.
        assert reader.last_sent == bytes.fromhex("FF000000") + b"\x03\xd4\x42\x60"

    def test_strips_the_reply_header(self):
        reader = StubACR122U([pn532_reply(b"\xaa\xbb")])
        assert reader.transceive(b"\x30\x04") == b"\xaa\xbb"

    def test_pn532_error_status_is_raised_not_returned(self):
        # 0x0A is the PN532 saying the tag left the field. Returning the empty
        # payload here would look like a successful read of nothing.
        reader = StubACR122U([pn532_reply(status=0x0A)])
        with pytest.raises(ReaderError, match="left the field"):
            reader.transceive(b"\x60")

    def test_unknown_pn532_error_reports_its_code(self):
        reader = StubACR122U([pn532_reply(status=0x7F)])
        with pytest.raises(ReaderError, match="0x7F"):
            reader.transceive(b"\x60")

    def test_a_reply_that_is_not_a_pn532_frame_is_rejected(self):
        reader = StubACR122U([(b"\x00\x01\x02", 0x90, 0x00)])
        with pytest.raises(ReaderError, match="unexpected answer"):
            reader.transceive(b"\x60")

    def test_follows_a_61xx_status_with_get_response(self):
        reader = StubACR122U([(b"", 0x61, 0x0B), pn532_reply(NTAG213_VERSION)])
        assert reader.transceive(b"\x60") == NTAG213_VERSION
        assert reader.sent[-1] == bytes.fromhex("FFC000000B")

    def test_a_failing_status_word_still_raises(self):
        reader = StubACR122U([(b"", 0x63, 0x00)])
        with pytest.raises(ApduError):
            reader.transceive(b"\x60")

    def test_empty_payload_is_a_programming_error(self):
        reader = StubACR122U()
        with pytest.raises(ValueError, match="at least one byte"):
            reader.transceive(b"")

    def test_payload_too_long_for_one_frame(self):
        reader = StubACR122U()
        with pytest.raises(ValueError, match="too long"):
            reader.transceive(b"\x00" * 254)


class TestPeripherals:
    def test_buzzer_off_matches_the_original_script(self):
        reader = StubACR122U()
        reader.set_buzzer(False)
        assert reader.last_sent == bytes.fromhex("FF00520000")

    def test_buzzer_on(self):
        reader = StubACR122U()
        reader.set_buzzer(True)
        assert reader.last_sent == bytes.fromhex("FF0052FF00")

    @pytest.mark.parametrize(
        ("red", "green", "state"),
        [(False, False, 0x0C), (True, False, 0x0D), (False, True, 0x0E), (True, True, 0x0F)],
    )
    def test_led_state_bits(self, red, green, state):
        reader = StubACR122U()
        reader.set_led(red=red, green=green)
        assert reader.last_sent == bytes([0xFF, 0x00, 0x40, state, 0x04, 0, 0, 0, 0])

    def test_firmware_version_reads_the_status_word_as_payload(self):
        # Captured from a real ACR122U: the last two characters of the string arrive
        # where a status word would normally be, so 0x31 0x34 is "14", not an error.
        reader = StubACR122U([(b"ACR122U2", 0x31, 0x34)])
        assert reader.firmware_version() == "ACR122U214"
        assert reader.last_sent == bytes.fromhex("FF00480000")
