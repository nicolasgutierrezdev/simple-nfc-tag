"""The exception hierarchy: one root, three branches, useful messages."""

from __future__ import annotations

import pytest

import simple_nfc_tag as snt
from simple_nfc_tag import exceptions as exc


@pytest.mark.parametrize(
    ("error", "branch"),
    [
        (exc.NoReaderFound, exc.ReaderError),
        (exc.ReaderNotSupported, exc.ReaderError),
        (exc.NoCardPresent, exc.CardError),
        (exc.CardRemoved, exc.CardError),
        (exc.UnsupportedCard, exc.CardError),
        (exc.AuthenticationError, exc.CardError),
        (exc.ApduError, exc.CardError),
        (exc.CardFull, exc.CardError),
        (exc.DecodeError, exc.FormatError),
        (exc.UnknownFormat, exc.FormatError),
        (exc.NdefNotSupported, exc.FormatError),
    ],
)
def test_every_error_sits_under_its_branch_and_under_nfcerror(error, branch):
    assert issubclass(error, branch)
    assert issubclass(error, exc.NfcError)


def test_apdu_error_exposes_the_status_bytes():
    error = exc.ApduError(0x6A, 0x82)
    assert (error.sw1, error.sw2) == (0x6A, 0x82)
    assert error.status_word == 0x6A82
    assert error.apdu is None


def test_apdu_error_decodes_the_dynamic_status_words():
    assert "card expects 16" in str(exc.ApduError(0x6C, 0x10))
    assert "8 response bytes available" in str(exc.ApduError(0x61, 0x08))


def test_card_full_reports_the_shortfall():
    error = exc.CardFull(needed=64, available=48)
    assert (error.needed, error.available) == (64, 48)
    assert "64" in str(error)
    assert "48" in str(error)


def test_ndef_points_at_the_workaround():
    assert "format='raw'" in str(exc.NdefNotSupported())


def test_exceptions_are_reachable_from_the_package_root():
    assert snt.ApduError is exc.ApduError
    assert issubclass(snt.CardRemoved, snt.NfcError)
