"""Driver selection from the PC/SC reader name."""

from __future__ import annotations

import pytest

from simple_nfc_tag import readers
from simple_nfc_tag.exceptions import NoReaderFound
from simple_nfc_tag.readers import ACR122U, PCSCReader, driver_for, open_reader

ACR122U_NAME = "ACS ACR122U PICC Interface 0"
OTHER_NAME = "Generic USB Smart Card Reader 0"


@pytest.fixture
def attached(monkeypatch):
    """Pretend a given set of readers is plugged in."""

    def _attach(*names):
        monkeypatch.setattr(readers, "list_readers", lambda: list(names))

    return _attach


class TestDriverSelection:
    def test_an_acr122u_gets_its_own_driver(self):
        assert driver_for(ACR122U_NAME) is ACR122U

    def test_matching_is_case_insensitive(self):
        assert driver_for("acs acr122u picc interface 0") is ACR122U

    def test_anything_else_falls_back_to_standard_pcsc(self):
        # The fallback has to be a working reader, not an error: a reader we have no
        # driver for still speaks the standardised commands.
        assert driver_for(OTHER_NAME) is PCSCReader

    def test_a_driver_needs_something_to_match_on(self):
        class Nameless(PCSCReader):
            pass

        with pytest.raises(ValueError, match="match"):
            readers.register_reader(Nameless)


class TestOpenReader:
    def test_takes_the_first_reader_by_default(self, attached):
        attached(ACR122U_NAME, OTHER_NAME)
        reader = open_reader()
        assert isinstance(reader, ACR122U)
        assert reader.name == ACR122U_NAME

    def test_selects_by_name_substring(self, attached):
        attached(ACR122U_NAME, OTHER_NAME)
        reader = open_reader("Generic")
        assert type(reader) is PCSCReader
        assert reader.name == OTHER_NAME

    def test_no_readers_attached(self, attached):
        attached()
        with pytest.raises(NoReaderFound, match="no PC/SC reader is attached"):
            open_reader()

    def test_an_unmatched_name_lists_what_is_actually_there(self, attached):
        attached(ACR122U_NAME)
        with pytest.raises(NoReaderFound) as excinfo:
            open_reader("OMNIKEY")
        assert ACR122U_NAME in str(excinfo.value)

    def test_the_reader_is_not_connected_yet(self, attached):
        # open_reader builds a driver; connect() is a separate, explicit step.
        attached(ACR122U_NAME)
        assert not open_reader().is_connected
