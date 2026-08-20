"""The Reader base class: APDU construction, status-word handling, connection state."""

from __future__ import annotations

import pytest

from simple_nfc_tag.exceptions import (
    ApduError,
    CardRemoved,
    NoCardPresent,
    ReaderNotSupported,
)
from simple_nfc_tag.keys import FACTORY_KEY, KeyType
from support import SUCCESS, StubReader


class TestApduConstruction:
    """The pseudo-APDUs are the contract cards are written against; pin the bytes."""

    def test_get_uid(self):
        reader = StubReader([(b"\x04\xa2\x24\x1a", 0x90, 0x00)])
        assert reader.get_uid() == b"\x04\xa2\x24\x1a"
        assert reader.last_sent == b"\xff\xca\x00\x00\x00"

    def test_read_binary(self):
        reader = StubReader([(bytes(16), 0x90, 0x00)])
        reader.read_binary(4, 16)
        assert reader.last_sent == b"\xff\xb0\x00\x04\x10"

    def test_update_binary_carries_the_payload(self):
        reader = StubReader()
        reader.update_binary(6, b"\x01\x02\x03\x04")
        assert reader.last_sent == b"\xff\xd6\x00\x06\x04\x01\x02\x03\x04"

    def test_load_key(self):
        reader = StubReader()
        reader.load_key(0, FACTORY_KEY)
        assert reader.last_sent == b"\xff\x82\x00\x00\x06" + FACTORY_KEY

    def test_authenticate_encodes_key_type_and_slot(self):
        reader = StubReader()
        reader.authenticate(4, KeyType.B, slot=1)
        assert reader.last_sent == b"\xff\x86\x00\x00\x05\x01\x00\x04\x61\x01"

    @pytest.mark.parametrize("block", [-1, 256])
    def test_block_address_must_fit_one_byte(self, block):
        reader = StubReader()
        with pytest.raises(ValueError, match="out of range"):
            reader.read_binary(block, 16)
        assert reader.sent == []

    def test_key_must_be_six_bytes(self):
        reader = StubReader()
        with pytest.raises(ValueError, match="6 bytes"):
            reader.load_key(0, b"\xff" * 5)


class TestStatusWords:
    """Nothing but 90 00 is success."""

    def test_non_success_raises(self):
        reader = StubReader([(b"", 0x63, 0x00)])
        with pytest.raises(ApduError) as excinfo:
            reader.get_uid()
        assert excinfo.value.status_word == 0x6300

    def test_error_names_the_condition_and_the_command(self):
        reader = StubReader([(b"", 0x69, 0x82)])
        with pytest.raises(ApduError) as excinfo:
            reader.read_binary(4, 16)
        message = str(excinfo.value)
        assert "SW=6982" in message
        assert "authentication required" in message
        assert "FF B0 00 04 10" in message

    def test_transmit_raw_reports_the_status_instead_of_raising(self):
        reader = StubReader([(b"", 0x6A, 0x82)])
        data, sw1, sw2 = reader.transmit_raw(b"\xff\xb0\x00\xff\x10")
        assert (data, sw1, sw2) == (b"", 0x6A, 0x82)

    def test_short_read_is_an_error_not_a_truncated_result(self):
        # A reader answering 90 00 with fewer bytes than asked for would otherwise
        # shorten a payload silently.
        reader = StubReader([(bytes(8), 0x90, 0x00)])
        with pytest.raises(ApduError):
            reader.read_binary(4, 16)

    def test_unknown_status_word_still_reports_its_value(self):
        reader = StubReader([(b"", 0x12, 0x34)])
        with pytest.raises(ApduError, match="SW=1234"):
            reader.get_uid()


class TestConnectionLifecycle:
    """Reader handle and card connection have different lifetimes."""

    def test_connect_is_idempotent(self):
        reader = StubReader()
        reader.connect()
        reader.connect()
        assert reader.acquire_count == 1
        assert reader.is_connected

    def test_reader_handle_needs_no_tag(self):
        reader = StubReader(present=False)
        with reader:
            assert reader.is_connected
            assert not reader.has_card_connection

    def test_card_connection_is_opened_once_and_reused(self):
        reader = StubReader()
        reader.get_uid()
        reader.get_uid()
        assert reader.open_count == 1
        assert len(reader.sent) == 2

    def test_empty_field_raises_rather_than_returning_nothing(self):
        reader = StubReader(present=False)
        with pytest.raises(NoCardPresent):
            reader.get_uid()

    def test_removal_mid_exchange_drops_the_dead_connection(self):
        reader = StubReader([SUCCESS, CardRemoved("gone")])
        reader.get_uid()
        assert reader.has_card_connection

        with pytest.raises(CardRemoved):
            reader.get_uid()
        assert not reader.has_card_connection
        assert reader.close_count == 1

    def test_disconnect_releases_both_handles(self):
        reader = StubReader()
        reader.get_uid()
        reader.disconnect()
        assert reader.close_count == 1
        assert reader.release_count == 1
        assert not reader.is_connected

    def test_context_manager_cleans_up_after_an_error(self):
        reader = StubReader([(b"", 0x6D, 0x00)])
        with reader, pytest.raises(ApduError):
            reader.get_uid()
        assert reader.release_count == 1
        assert not reader.has_card_connection

    def test_atr_comes_from_the_card_connection(self):
        reader = StubReader()
        assert reader.get_atr() == reader.atr
        assert reader.open_count == 1


class TestOptionalCapabilities:
    def test_transceive_is_unsupported_by_default(self):
        reader = StubReader()
        with pytest.raises(ReaderNotSupported, match="GET_VERSION"):
            reader.transceive(b"\x60\x00")

    def test_peripherals_are_no_ops_not_errors(self):
        reader = StubReader()
        reader.set_buzzer(False)
        reader.set_led(green=True)
        assert reader.sent == []
