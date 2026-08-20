"""The cached-connection core: current_tag(), wait_for_tag(), and identification.

These pin one connection and one identification per card presence, however many times
the caller asks.
"""

from __future__ import annotations

import pytest

from simple_nfc_tag.cards import identify, known_drivers, register_driver
from simple_nfc_tag.cards.atr import parse_atr
from simple_nfc_tag.exceptions import CardRemoved, UnsupportedCard
from support import (
    CLASSIC_1K_ATR,
    ULTRALIGHT_ATR,
    UNKNOWN_ATR,
    Card,
    StubReader,
    driver_registered,
)

UID_A = b"\x04\x9a\xee\xe2\x30\x73\x80"
UID_B = b"\x04\x11\x22\x33\x44\x55\x66"


class AnyTag(Card):
    """A driver that claims every tag, so the caching logic can be exercised alone."""

    product = "AnyTag"
    block_size = 4
    probes = 0

    @classmethod
    def probe(cls, reader, atr, uid):
        cls.probes += 1
        return cls(reader, uid)

    def _user_blocks(self):
        return (4, 5, 6, 7)

    def read_block(self, index):
        return bytes(4)

    def write_block(self, index, data):
        pass


@pytest.fixture
def any_tag_driver():
    AnyTag.probes = 0
    with driver_registered(AnyTag):
        yield AnyTag


def uid_reply(uid: bytes):
    return (uid, 0x90, 0x00)


class TestIdentify:
    def test_no_driver_claims_the_tag(self):
        reader = StubReader([uid_reply(UID_A)], atr=UNKNOWN_ATR)
        with pytest.raises(UnsupportedCard) as excinfo:
            identify(reader)
        message = str(excinfo.value)
        # The message carries what the ATR said and which tag it was.
        assert "0xABCD" in message
        assert UID_A.hex().upper() in message

    def test_a_registered_driver_claims_it(self, any_tag_driver):
        reader = StubReader([uid_reply(UID_A)])
        card = identify(reader)
        assert isinstance(card, AnyTag)
        assert card.uid == UID_A

    def test_a_later_driver_takes_precedence(self, any_tag_driver):
        class Fussy(Card):
            product = "Fussy"

            @classmethod
            def probe(cls, reader, atr, uid):
                return None

            def _user_blocks(self):
                return ()

            def read_block(self, index):
                return b""

            def write_block(self, index, data):
                pass

        with driver_registered(Fussy):
            order = known_drivers()
            # Registering later is how a caller overrides a driver this package ships.
            assert order.index(Fussy) < order.index(AnyTag)

    def test_registering_twice_does_not_duplicate(self, any_tag_driver):
        register_driver(AnyTag)
        assert known_drivers().count(AnyTag) == 1


class TestCurrentTag:
    def test_empty_field_returns_none(self):
        reader = StubReader(present=False)
        assert reader.current_tag() is None

    def test_identifies_once_per_presence(self, any_tag_driver):
        reader = StubReader(default=uid_reply(UID_A))
        first = reader.current_tag()
        second = reader.current_tag()
        third = reader.current_tag()

        assert first is second is third
        assert AnyTag.probes == 1
        assert reader.open_count == 1

    def test_repeat_calls_cost_one_uid_probe(self, any_tag_driver):
        reader = StubReader(default=uid_reply(UID_A))
        reader.current_tag()
        before = len(reader.sent)
        reader.current_tag()
        assert len(reader.sent) - before == 1
        assert reader.last_sent == b"\xff\xca\x00\x00\x00"

    def test_a_swapped_tag_is_re_identified(self, any_tag_driver):
        reader = StubReader(default=uid_reply(UID_A))
        first = reader.current_tag()

        reader.default = uid_reply(UID_B)
        second = reader.current_tag()

        assert second is not first
        assert second.uid == UID_B
        assert AnyTag.probes == 2
        assert reader.close_count == 1

    def test_removal_drops_the_connection_and_the_tag(self, any_tag_driver):
        reader = StubReader(default=uid_reply(UID_A))
        reader.current_tag()

        reader.present = False
        reader.answer(CardRemoved("gone"))
        assert reader.current_tag() is None
        assert not reader.has_card_connection

    def test_a_tag_returning_after_removal_is_identified_again(self, any_tag_driver):
        reader = StubReader(default=uid_reply(UID_A))
        reader.current_tag()

        reader.present = False
        reader.answer(CardRemoved("gone"))
        assert reader.current_tag() is None

        reader.present = True
        assert reader.current_tag() is not None
        assert AnyTag.probes == 2

    def test_an_unsupported_tag_still_raises_on_every_call(self):
        # A present-but-unknown tag is not an empty field.
        reader = StubReader(default=uid_reply(UID_A), atr=UNKNOWN_ATR)
        with pytest.raises(UnsupportedCard):
            reader.current_tag()


class TestWaitForTag:
    def test_returns_immediately_when_a_tag_is_there(self, any_tag_driver):
        reader = StubReader(default=uid_reply(UID_A))
        assert reader.wait_for_tag(timeout=5) is not None

    def test_returns_none_at_timeout_without_leaking_a_connection(self):
        reader = StubReader(present=False)
        assert reader.wait_for_tag(timeout=0.05, poll_interval=0.01) is None
        assert not reader.has_card_connection

    def test_picks_up_a_tag_presented_during_the_wait(self, any_tag_driver):
        reader = StubReader(present=False, default=uid_reply(UID_A))
        calls = {"n": 0}
        original = reader._open_card

        def present_on_third_look():
            calls["n"] += 1
            if calls["n"] >= 3:
                reader.present = True
            return original()

        reader._open_card = present_on_third_look
        tag = reader.wait_for_tag(timeout=2, poll_interval=0.01)
        assert tag is not None
        assert calls["n"] >= 3

    def test_poll_interval_must_be_positive(self):
        reader = StubReader(present=False)
        with pytest.raises(ValueError, match="poll_interval"):
            reader.wait_for_tag(timeout=1, poll_interval=0)


class TestAtrDecoding:
    def test_reads_the_card_name_from_a_real_ultralight_atr(self):
        info = parse_atr(ULTRALIGHT_ATR)
        assert info.card_name == 0x0003
        assert info.standard == 0x03
        assert info.product == "MIFARE Ultralight"

    def test_reads_a_classic_1k(self):
        info = parse_atr(CLASSIC_1K_ATR)
        assert info.card_name == 0x0001
        assert info.product == "MIFARE Classic 1K"

    def test_an_atr_without_the_pcsc_rid_says_so_instead_of_guessing(self):
        info = parse_atr(bytes.fromhex("3B00"))
        assert info.card_name is None
        assert info.product == "unknown"

    def test_a_truncated_atr_does_not_raise(self):
        info = parse_atr(bytes.fromhex("3B8F8001804F0CA000000306"))
        assert info.card_name is None

    def test_an_unregistered_card_name_is_reported_by_value(self):
        atr = bytearray(ULTRALIGHT_ATR)
        atr[13:15] = b"\xab\xcd"
        assert "0xABCD" in parse_atr(bytes(atr)).product
