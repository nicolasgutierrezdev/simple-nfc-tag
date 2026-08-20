"""NTAG21x passwords: PWD_AUTH, setting one, and what protection actually covers."""

from __future__ import annotations

import pytest

from simple_nfc_tag.cards import identify
from simple_nfc_tag.exceptions import (
    ApduError,
    AuthenticationError,
    CardError,
    ReaderNotSupported,
    WriteVerificationError,
)
from simple_nfc_tag.readers.fake import FakeNTAG213, FakeReader, FakeUltralight

PASSWORD = bytes.fromhex("DEADBEEF")
PACK = bytes.fromhex("A1B2")
WRONG = bytes.fromhex("00000000")
NEW_PASSWORD = bytes.fromhex("0BADCAFE")
NEW_PACK = bytes.fromhex("C0DE")

#: NTAG213 user memory is pages 4-39; protect the back half of it.
PROTECT_FROM = 20


def protected_tag(**kwargs):
    kwargs.setdefault("protect_from", PROTECT_FROM)
    image = FakeNTAG213(password=PASSWORD, pack=PACK, **kwargs)
    reader = FakeReader(image)
    return identify(reader), reader, image


def offset_of(page: int) -> int:
    """Linear user-memory offset of a page. User memory starts at page 4."""
    return (page - 4) * 4


class TestAuthenticate:
    def test_the_right_password_returns_the_pack(self):
        tag, _, _ = protected_tag()
        assert tag.authenticate(PASSWORD) == PACK

    def test_the_pack_can_be_checked(self):
        tag, _, _ = protected_tag()
        assert tag.authenticate(PASSWORD, pack=PACK) == PACK

    def test_a_wrong_pack_is_an_error_even_though_the_password_worked(self):
        # A tag that takes the password but answers with the wrong PACK is not the
        # tag it claims to be.
        tag, _, _ = protected_tag()
        with pytest.raises(AuthenticationError, match="does not hold the password"):
            tag.authenticate(PASSWORD, pack=b"\x00\x00")

    def test_a_wrong_password_is_refused(self):
        tag, _, _ = protected_tag()
        with pytest.raises(AuthenticationError, match="refused the password"):
            tag.authenticate(WRONG)

    def test_a_refused_password_leaves_the_tag_usable(self):
        # PWD_AUTH is NAKed, which deselects the tag. Without a session reset the
        # next read fails for a reason that has nothing to do with the password.
        tag, _, image = protected_tag()
        image.memory[16:20] = b"OPEN"
        with pytest.raises(AuthenticationError):
            tag.authenticate(WRONG)
        assert tag.read_bytes(0, 4) == b"OPEN"

    @pytest.mark.parametrize("password", [b"", b"\x01\x02\x03", b"\x01\x02\x03\x04\x05"])
    def test_the_password_must_be_four_bytes(self, password):
        tag, _, _ = protected_tag()
        with pytest.raises(ValueError, match="4 bytes"):
            tag.authenticate(password)

    def test_the_pack_must_be_two_bytes(self):
        tag, _, _ = protected_tag()
        with pytest.raises(ValueError, match="2 bytes"):
            tag.authenticate(PASSWORD, pack=b"\x01")

    def test_a_reader_without_a_passthrough_says_so(self):
        image = FakeNTAG213(password=PASSWORD, pack=PACK)
        reader = FakeReader(image, supports_transceive=False)
        tag = identify(reader)
        with pytest.raises(ReaderNotSupported):
            tag.authenticate(PASSWORD)

    def test_an_unprotected_tag_has_no_password_to_prove(self):
        tag = identify(FakeReader(FakeNTAG213()))
        with pytest.raises(AuthenticationError):
            tag.authenticate(PASSWORD)


class TestProtection:
    def test_protection_covers_writes_but_not_reads_by_default(self):
        # AUTH0 alone protects writes only. Protected pages stay readable by anyone
        # until the PROT bit in CFG1 is set as well.
        tag, _, image = protected_tag()
        image.memory[PROTECT_FROM * 4 : PROTECT_FROM * 4 + 4] = b"OPEN"

        assert tag.read_bytes(offset_of(PROTECT_FROM), 4) == b"OPEN"

        # The refused write is not reported as one: the reader answers 90 00, so only
        # reading the bytes back catches it.
        with pytest.raises(WriteVerificationError):
            tag.write_bytes(offset_of(PROTECT_FROM), b"MINE")
        assert bytes(image.memory[PROTECT_FROM * 4 : PROTECT_FROM * 4 + 4]) == b"OPEN"

    def test_a_refused_write_looks_like_success_with_verify_off(self):
        # What verify= covers: without the read-back nothing tells the caller the
        # bytes never landed.
        tag, _, image = protected_tag()
        image.memory[PROTECT_FROM * 4 : PROTECT_FROM * 4 + 4] = b"OPEN"

        tag.write_bytes(offset_of(PROTECT_FROM), b"MINE", verify=False)
        assert bytes(image.memory[PROTECT_FROM * 4 : PROTECT_FROM * 4 + 4]) == b"OPEN"

    def test_the_prot_bit_protects_reads_too(self):
        tag, _, _ = protected_tag(protect_reads=True)
        with pytest.raises(ApduError):
            tag.read_bytes(offset_of(PROTECT_FROM), 4)

    def test_authenticating_opens_protected_pages_for_reading(self):
        tag, _, image = protected_tag(protect_reads=True)
        image.memory[PROTECT_FROM * 4 : PROTECT_FROM * 4 + 4] = b"LOCK"

        tag.authenticate(PASSWORD)
        assert tag.read_bytes(offset_of(PROTECT_FROM), 4) == b"LOCK"

    def test_authenticating_opens_protected_pages_for_writing(self):
        tag, _, image = protected_tag()
        tag.authenticate(PASSWORD)
        tag.write_bytes(offset_of(PROTECT_FROM), b"MINE")
        assert bytes(image.memory[PROTECT_FROM * 4 : PROTECT_FROM * 4 + 4]) == b"MINE"

    def test_pages_below_auth0_are_never_protected(self):
        tag, _, image = protected_tag(protect_reads=True)
        image.memory[16:20] = b"FREE"
        assert tag.read_bytes(0, 4) == b"FREE"
        tag.write_bytes(0, b"OPEN")
        assert bytes(image.memory[16:20]) == b"OPEN"

    def test_the_password_is_forgotten_when_the_tag_leaves_the_field(self):
        # Authentication lasts one RF session, the same lifetime as the card object.
        tag, reader, image = protected_tag()
        tag.authenticate(PASSWORD)
        assert image.authenticated

        reader.drop_card_connection()
        reader.open_card_connection()
        assert not image.authenticated


class StubbornTag(FakeNTAG213):
    """A tag that quietly ignores writes to its password page.

    Stands in for anything that leaves the stored password other than what the caller
    believes: a locked configuration, a counterfeit, a flaky write.
    """

    def write(self, block: int, data: bytes) -> None:
        if block == self.config_page + 2:
            self.writes.append(block)
            return
        super().write(block, data)


class TestSetPassword:
    def test_the_password_is_changed(self):
        tag, _, image = protected_tag(protect_from=None)
        tag.set_password(NEW_PASSWORD, NEW_PACK)
        assert image.password == NEW_PASSWORD
        assert image.pack == NEW_PACK

    def test_the_new_password_authenticates_and_the_old_one_does_not(self):
        tag, reader, _ = protected_tag(protect_from=None)
        tag.set_password(NEW_PASSWORD, NEW_PACK)

        assert tag.authenticate(NEW_PASSWORD, pack=NEW_PACK) == NEW_PACK
        reader.reset_card_connection()
        with pytest.raises(AuthenticationError):
            tag.authenticate(PASSWORD)

    def test_the_password_cannot_be_read_back(self):
        # A password can only be recorded outside the tag.
        tag, reader, _ = protected_tag(protect_from=None)
        tag.set_password(NEW_PASSWORD, NEW_PACK)

        config = tag.total_pages - 4
        assert reader.read_binary(config + 2, 4) == bytes(4)
        assert reader.read_binary(config + 3, 4) == bytes(4)

    def test_protection_is_left_alone_by_default(self):
        tag, _, image = protected_tag(protect_from=None)
        tag.set_password(NEW_PASSWORD, NEW_PACK)
        assert image.protect_from is None

    def test_protection_can_be_enabled(self):
        tag, _, image = protected_tag(protect_from=None)
        tag.set_password(NEW_PASSWORD, NEW_PACK, protect_from=20)
        assert image.protect_from == 20

    def test_protection_can_be_disabled(self):
        tag, _, image = protected_tag()
        assert image.protect_from == PROTECT_FROM

        tag.authenticate(PASSWORD)
        tag.set_password(PASSWORD, PACK, protect_from=0xFF)
        assert image.protect_from is None

    def test_the_rest_of_cfg0_is_preserved(self):
        # CFG0 also carries the mirror configuration; only AUTH0 may change.
        tag, reader, _ = protected_tag(protect_from=None)
        config = tag.total_pages - 4
        before = reader.read_binary(config, 4)

        tag.set_password(NEW_PASSWORD, NEW_PACK, protect_from=20)
        after = reader.read_binary(config, 4)
        assert after[:3] == before[:3]
        assert after[3] == 20

    def test_cfg1_is_left_alone_when_protect_reads_is_not_asked_for(self):
        tag, reader, _ = protected_tag(protect_from=None)
        config = tag.total_pages - 4
        before = reader.read_binary(config + 1, 4)

        tag.set_password(NEW_PASSWORD, NEW_PACK, protect_from=20)
        assert reader.read_binary(config + 1, 4) == before

    def test_reads_can_be_protected(self):
        tag, _, image = protected_tag(protect_from=None)
        assert not image.protect_reads

        tag.set_password(NEW_PASSWORD, NEW_PACK, protect_from=20, protect_reads=True)
        assert image.protect_reads
        assert image.protect_from == 20

    def test_read_protection_can_be_lifted_without_dropping_the_password(self):
        tag, _, image = protected_tag(protect_reads=True)
        tag.authenticate(PASSWORD)

        tag.set_password(PASSWORD, PACK, protect_reads=False)
        assert not image.protect_reads
        # AUTH0 was not asked about, so writes stay protected.
        assert image.protect_from == PROTECT_FROM

    def test_setting_prot_actually_closes_reads_on_the_tag(self):
        # Checked through the public read path rather than by looking at CFG1.
        tag, reader, image = protected_tag(protect_from=None)
        image.memory[PROTECT_FROM * 4 : PROTECT_FROM * 4 + 4] = b"MINE"

        tag.set_password(NEW_PASSWORD, NEW_PACK, protect_from=PROTECT_FROM, protect_reads=True)
        # set_password leaves the session authenticated, so the page is still open here.
        assert tag.read_bytes(offset_of(PROTECT_FROM), 4) == b"MINE"

        # On the next presentation it is not: PWD_AUTH lasts one RF session.
        reader.drop_card_connection()
        reader.open_card_connection()
        with pytest.raises(ApduError):
            tag.read_bytes(offset_of(PROTECT_FROM), 4)

    def test_the_rest_of_cfg1_is_preserved(self):
        # CFG1 also carries AUTHLIM in the low bits of the same ACCESS byte, and the
        # mirror page and RFUI bytes after it. Only PROT may change.
        tag, reader, _ = protected_tag(protect_from=None)
        config = tag.total_pages - 4
        before = reader.read_binary(config + 1, 4)

        tag.set_password(NEW_PASSWORD, NEW_PACK, protect_reads=True)
        after = reader.read_binary(config + 1, 4)
        assert after[0] == before[0] | 0x80
        assert after[1:] == before[1:]

    def test_prot_is_not_set_when_the_password_did_not_take(self):
        # Same guard as AUTH0: closing reads behind a password the tag never stored is
        # the unrecoverable direction.
        image = StubbornTag(password=PASSWORD, pack=PACK)
        tag = identify(FakeReader(image))

        with pytest.raises(AuthenticationError):
            tag.set_password(NEW_PASSWORD, NEW_PACK, protect_reads=True)
        assert not image.protect_reads

    def test_authlim_is_never_touched(self):
        # AUTHLIM shares the ACCESS byte with PROT, and a non-zero one can brick a
        # tag, so setting PROT must not disturb it.
        tag, reader, _ = protected_tag(protect_from=None)
        config = tag.total_pages - 4
        reader.update_binary(config + 1, bytes([0x03]) + reader.read_binary(config + 1, 4)[1:])

        tag.set_password(NEW_PASSWORD, NEW_PACK, protect_reads=True)
        assert reader.read_binary(config + 1, 4)[0] == 0x83

    def test_protection_is_not_enabled_when_the_password_did_not_take(self):
        # If the tag kept its old password, enabling protection would lock pages behind
        # a secret nobody has, and a non-zero AUTHLIM makes that permanent.
        image = StubbornTag(password=PASSWORD, pack=PACK)
        tag = identify(FakeReader(image))

        with pytest.raises(AuthenticationError):
            tag.set_password(NEW_PASSWORD, NEW_PACK, protect_from=20)
        assert image.protect_from is None

    def test_a_plain_ultralight_has_no_password_pages(self):
        tag = identify(FakeReader(FakeUltralight()))
        with pytest.raises(CardError, match="NTAG21x feature"):
            tag.set_password(NEW_PASSWORD, NEW_PACK)

    @pytest.mark.parametrize("password", [b"", b"\x01\x02\x03"])
    def test_the_password_must_be_four_bytes(self, password):
        tag, _, _ = protected_tag(protect_from=None)
        with pytest.raises(ValueError, match="4 bytes"):
            tag.set_password(password, NEW_PACK)

    def test_the_pack_must_be_two_bytes(self):
        tag, _, _ = protected_tag(protect_from=None)
        with pytest.raises(ValueError, match="2 bytes"):
            tag.set_password(NEW_PASSWORD, b"\x01")

    @pytest.mark.parametrize("page", [-1, 256])
    def test_protect_from_must_be_a_page_number(self, page):
        tag, _, _ = protected_tag(protect_from=None)
        with pytest.raises(ValueError, match="page number"):
            tag.set_password(NEW_PASSWORD, NEW_PACK, protect_from=page)
