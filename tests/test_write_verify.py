"""Write verification: reading the bytes back, because a refused write can report success.

Measured on an ACR122U with an NTAG213: a write to a page protected by ``AUTH0``
answers ``90 00`` and changes nothing. The fake NTAG images reproduce it, so this runs
with no reader attached.
"""

from __future__ import annotations

import pytest

from simple_nfc_tag.cards import identify
from simple_nfc_tag.exceptions import WriteVerificationError
from simple_nfc_tag.readers.fake import FakeClassic1K, FakeNTAG213, FakeReader

PASSWORD = bytes.fromhex("DEADBEEF")
PACK = bytes.fromhex("A1B2")

#: NTAG213 user memory is pages 4-39. Protect from page 20, halfway up.
PROTECT_FROM = 20
#: Linear offset of the first protected page.
PROTECTED_AT = (PROTECT_FROM - 4) * 4


def protected_ntag():
    image = FakeNTAG213(password=PASSWORD, pack=PACK, protect_from=PROTECT_FROM)
    reader = FakeReader(image)
    return identify(reader), reader, image


class TestVerifiedWrite:
    def test_a_write_that_lands_is_silent(self):
        tag = identify(FakeReader(FakeNTAG213()))
        tag.write_bytes(0, b"payload")
        assert tag.read_bytes(0, 7) == b"payload"

    def test_a_write_that_does_not_land_raises(self):
        tag, _, _ = protected_ntag()
        with pytest.raises(WriteVerificationError):
            tag.write_bytes(PROTECTED_AT, b"MINE")

    def test_verify_false_lets_the_silent_failure_through(self):
        tag, _, image = protected_ntag()
        before = bytes(image.memory[PROTECT_FROM * 4 : PROTECT_FROM * 4 + 4])
        tag.write_bytes(PROTECTED_AT, b"MINE", verify=False)
        assert bytes(image.memory[PROTECT_FROM * 4 : PROTECT_FROM * 4 + 4]) == before

    def test_the_error_names_the_first_byte_that_is_wrong(self):
        tag, _, image = protected_ntag()
        image.memory[PROTECT_FROM * 4 : PROTECT_FROM * 4 + 4] = b"KEEP"

        with pytest.raises(WriteVerificationError) as excinfo:
            tag.write_bytes(PROTECTED_AT, b"KEMP")

        error = excinfo.value
        assert error.offset == PROTECTED_AT
        assert error.expected == b"KEMP"
        assert error.actual == b"KEEP"
        # Byte 2 is the first difference: M against E.
        assert f"byte {PROTECTED_AT + 2}" in str(error)
        assert "0x4D" in str(error)
        assert "0x45" in str(error)

    def test_the_deselect_does_not_mask_the_real_error(self):
        # A refused NTAG write deselects the tag, so the verifying read trips over it.
        # The caller must still hear "the bytes are wrong", not an ApduError.
        tag, reader, _ = protected_ntag()
        with pytest.raises(WriteVerificationError):
            tag.write_bytes(PROTECTED_AT, b"MINE")
        assert reader.resets == 1

    def test_authenticating_first_makes_the_write_verify(self):
        tag, _, _ = protected_ntag()
        tag.authenticate(PASSWORD)
        tag.write_bytes(PROTECTED_AT, b"MINE")
        assert tag.read_bytes(PROTECTED_AT, 4) == b"MINE"

    def test_an_unprotected_page_is_unaffected(self):
        tag, _, _ = protected_ntag()
        tag.write_bytes(0, b"FREE")
        assert tag.read_bytes(0, 4) == b"FREE"


class TestCost:
    """What the read-back actually costs, in APDUs, on each family."""

    def test_an_ntag_read_back_is_a_quarter_of_the_write_run(self):
        # A page is written one at a time; a read returns four pages at once.
        tag = identify(FakeReader(FakeNTAG213()))
        reader = tag.reader
        payload = bytes(64)  # 16 pages

        before = len(reader.sent)
        tag.write_bytes(0, payload, verify=False)
        writes = len(reader.sent) - before

        before = len(reader.sent)
        tag.write_bytes(0, payload)
        verified = len(reader.sent) - before

        assert writes == 16
        assert verified == writes + 4

    def test_a_classic_read_back_is_one_read_per_block(self):
        tag = identify(FakeReader(FakeClassic1K()))
        reader = tag.reader
        payload = bytes(48)  # 3 blocks, all inside sector 1

        # Warm up first, or the unverified run pays for the LOAD KEY and AUTHENTICATE
        # that open sector 1 and the comparison measures that instead.
        tag.write_bytes(0, payload, verify=False)

        before = len(reader.sent)
        tag.write_bytes(0, payload, verify=False)
        writes = len(reader.sent) - before

        before = len(reader.sent)
        tag.write_bytes(0, payload)
        verified = len(reader.sent) - before

        # The sector is already open for the read-back: reads only, no second
        # authentication.
        assert verified == writes + 3


class TestClassicSessionCache:
    def test_a_rebuilt_session_invalidates_the_open_sector(self):
        # Verification can rebuild the RF session. A Classic still believing its
        # sector is open would skip the authentication the next read needs.
        tag = identify(FakeReader(FakeClassic1K()))
        tag.read_bytes(0, 16)
        assert tag.authenticated_sector == 1

        tag._session_restarted()
        assert tag.authenticated_sector is None

        # It recovers by authenticating again rather than failing.
        assert len(tag.read_bytes(0, 16)) == 16
        assert tag.authenticated_sector == 1
