"""Outer framing, the lazy cursor, and the two v1 codecs."""

from __future__ import annotations

import pytest

from simple_nfc_tag.codecs import framing
from simple_nfc_tag.codecs.base import (
    _CODECS,
    ByteCursor,
    codec_for,
    decode_auto,
    detect_codec,
    known_codecs,
    register_codec,
)
from simple_nfc_tag.codecs.raw import RawCodec
from simple_nfc_tag.codecs.tlv import CompactTlvCodec
from simple_nfc_tag.codecs.values import U16
from simple_nfc_tag.exceptions import (
    DecodeError,
    NdefNotSupported,
    UnknownFormat,
)

TLV = CompactTlvCodec()
RAW = RawCodec()


def cursor_over(data: bytes, chunk: int = 4, size: int | None = None) -> ByteCursor:
    """A cursor over a fixed byte string, counting what it actually fetched."""
    padded = data.ljust(size or len(data), b"\x00")

    def fetch(offset: int, length: int) -> bytes:
        return padded[offset : offset + length]

    return ByteCursor(fetch, len(padded), chunk)


class TestLengths:
    """One length rule for the whole format: one byte, or 0xFF plus two big-endian."""

    @pytest.mark.parametrize(
        ("length", "encoded"),
        [
            (0, "00"),
            (1, "01"),
            (127, "7F"),
            (128, "80"),  # no escape here: BER would need two bytes for this
            (254, "FE"),  # last short form
            (255, "FF00FF"),  # 0xFF is an escape, never a length
            (256, "FF0100"),
            (65535, "FFFFFF"),
        ],
    )
    def test_known_encodings(self, length, encoded):
        assert framing.encode_length(length).hex().upper() == encoded

    @pytest.mark.parametrize("length", [0, 1, 126, 127, 128, 129, 253, 254, 255, 256, 65535])
    def test_round_trip(self, length):
        encoded = framing.encode_length(length)
        assert framing.decode_length(encoded) == (length, len(encoded))

    def test_inner_values_use_the_same_rule_as_the_outer_block(self):
        # A length is a length wherever it appears: a 255-byte value is FF 00 FF at
        # both tiers, not 81 FF at one of them.
        payload = "x" * 255
        encoded = TLV.encode([payload])
        assert encoded[:1] == bytes([framing.PROPRIETARY])
        outer_length, after_outer = framing.decode_length(encoded, 1)
        assert framing.encode_length(outer_length) == encoded[1:after_outer]

        # Inner: type id, then the same length encoding.
        assert encoded[after_outer] == 0x01  # str
        inner_length, _ = framing.decode_length(encoded, after_outer + 1)
        assert inner_length == 255
        assert encoded[after_outer + 1 : after_outer + 4] == b"\xff\x00\xff"

    def test_too_long_for_a_type2_tlv(self):
        with pytest.raises(ValueError, match="cannot carry"):
            framing.encode_length(65536)

    def test_truncated_long_form(self):
        with pytest.raises(DecodeError, match="cut short"):
            framing.decode_length(b"\xff\x01")


class TestBlocks:
    def test_a_block_carries_tag_length_and_value(self):
        assert framing.encode_block(0xFD, b"abc") == b"\xfd\x03abc"

    @pytest.mark.parametrize("tag", [framing.NULL, framing.TERMINATOR])
    def test_single_byte_tags_have_no_length(self, tag):
        assert framing.encode_block(tag, b"") == bytes([tag])

    def test_a_single_byte_tag_cannot_carry_a_value(self):
        with pytest.raises(ValueError, match="carries no value"):
            framing.encode_block(framing.TERMINATOR, b"x")


class TestCursor:
    def test_reads_advance(self):
        cursor = cursor_over(b"abcdefgh")
        assert cursor.read(3) == b"abc"
        assert cursor.read(2) == b"de"
        assert cursor.position == 5

    def test_peek_does_not_advance(self):
        cursor = cursor_over(b"abcdefgh")
        assert cursor.peek(3) == b"abc"
        assert cursor.peek(3) == b"abc"
        assert cursor.position == 0

    def test_peek_past_the_end_returns_what_is_there(self):
        cursor = cursor_over(b"ab")
        assert cursor.peek(10) == b"ab"

    def test_reading_past_the_end_is_an_error(self):
        cursor = cursor_over(b"ab")
        with pytest.raises(DecodeError, match="only 2"):
            cursor.read(3)

    def test_fetches_are_chunked(self):
        cursor = cursor_over(bytes(64), chunk=16)
        cursor.read(1)
        # One byte asked for, one chunk fetched.
        assert cursor.fetched == 16

    def test_a_small_read_does_not_drain_the_tag(self):
        # Reading a 12-byte payload off an 888-byte NTAG216 must not fetch 888 bytes.
        cursor = cursor_over(b"\xfd\x0b" + bytes(886), chunk=16, size=888)
        cursor.read(14)
        assert cursor.fetched <= 32

    def test_read_rest_takes_everything_left(self):
        cursor = cursor_over(b"abcdef")
        cursor.read(2)
        assert cursor.read_rest() == b"cdef"
        assert cursor.remaining == 0

    def test_skip_advances_without_returning(self):
        cursor = cursor_over(b"abcdef")
        cursor.skip(2)
        assert cursor.read(1) == b"c"

    def test_negative_read(self):
        with pytest.raises(ValueError, match="negative"):
            cursor_over(b"ab").read(-1)


class TestCompactTlv:
    def test_the_documented_wire_format(self):
        # The worked example from the wire-format spec, byte for byte.
        encoded = TLV.encode(["ABC123", U16(42)])
        assert encoded.hex(" ").upper() == "FD 0C 01 06 41 42 43 31 32 33 02 02 00 2A FE"

    def test_auto_typing_uses_the_shortest_int(self):
        # Same value, no width wrapper: one byte instead of two.
        assert TLV.encode(["ABC123", 42]).hex(" ").upper() == (
            "FD 0B 01 06 41 42 43 31 32 33 02 01 2A FE"
        )

    @pytest.mark.parametrize(
        "values",
        [
            [],
            ["ABC123", 42],
            ["one"],
            [0, -1, True, False, 3.5, b"\x00\xff", "text"],
            [{"a": [1, 2]}, None],
            ["x" * 255],  # the length-escape boundary
            ["x" * 200],  # one byte of length under this rule, two under BER
            list(range(50)),
        ],
    )
    def test_round_trip(self, values):
        cursor = cursor_over(TLV.encode(values), size=1024)
        assert TLV.decode(cursor) == values

    def test_a_bare_value_becomes_a_one_element_sequence(self):
        cursor = cursor_over(TLV.encode("hello"), size=64)
        assert TLV.decode(cursor) == ["hello"]

    def test_bytes_are_one_value_not_a_sequence_of_ints(self):
        cursor = cursor_over(TLV.encode(b"abc"), size=64)
        assert TLV.decode(cursor) == [b"abc"]

    def test_a_tuple_is_a_sequence(self):
        cursor = cursor_over(TLV.encode(("a", "b")), size=64)
        assert TLV.decode(cursor) == ["a", "b"]

    def test_null_padding_before_the_payload_is_skipped(self):
        cursor = cursor_over(b"\x00\x00" + TLV.encode(["x"]), size=64)
        assert TLV.decode(cursor) == ["x"]

    def test_an_unrelated_tlv_is_stepped_over(self):
        other = framing.encode_block(0x01, b"lock control")
        cursor = cursor_over(other + TLV.encode(["x"]), size=64)
        assert TLV.decode(cursor) == ["x"]

    def test_detect(self):
        assert TLV.detect(b"\xfd\x0b")
        assert TLV.detect(b"\x00\x00\xfd")
        assert not TLV.detect(b"\x03\x10")
        assert not TLV.detect(b"")
        assert not TLV.detect(b"\x00\x00")

    def test_a_terminator_before_any_payload(self):
        cursor = cursor_over(b"\xfe", size=16)
        with pytest.raises(DecodeError, match="without a payload"):
            TLV.decode(cursor)

    def test_an_inner_value_claiming_too_many_bytes(self):
        # The outer block is 3 bytes long; the string inside it claims to be 200.
        cursor = cursor_over(b"\xfd\x03\x01\xc8\x00\xfe", size=16)
        with pytest.raises(DecodeError, match="claims 200 bytes"):
            TLV.decode(cursor)

    def test_an_ndef_message_is_named_rather_than_mangled(self):
        cursor = cursor_over(b"\x03\x03\xd0\x00\x00\xfe", size=16)
        with pytest.raises(NdefNotSupported):
            TLV.decode(cursor)


class TestRaw:
    def test_round_trip(self):
        payload = bytes(range(32))
        cursor = cursor_over(RAW.encode(payload))
        assert cursor.read_rest() == payload

    def test_decode_returns_all_of_user_memory(self):
        cursor = cursor_over(b"abc", size=16)
        assert RAW.decode(cursor) == b"abc".ljust(16, b"\x00")

    def test_bytearrays_are_accepted(self):
        assert RAW.encode(bytearray(b"ab")) == b"ab"

    def test_anything_else_is_refused_with_a_hint(self):
        with pytest.raises(TypeError, match="tlv format"):
            RAW.encode(["not", "bytes"])

    def test_raw_never_claims_a_payload(self):
        # Otherwise raw would win every auto-detected read.
        assert not RAW.detect(b"\xfd\x0b")
        assert not RAW.detect(b"anything")


class _GoodCodec:
    """The smallest thing that satisfies the codec protocol."""

    def __init__(self) -> None:
        self.name = "good"

    def encode(self, value):
        return b"GOOD" + str(value).encode()

    def decode(self, cursor):
        cursor.skip(4)
        return cursor.read_rest().rstrip(b"\x00").decode()

    def detect(self, head):
        return head.startswith(b"GOOD")


class _NoDetect:
    """A plausible mistake: the two obvious methods, but not the third."""

    name = "nodetect"

    def encode(self, value):
        return b""

    def decode(self, cursor):
        return None


class _Nameless:
    """Methods but no name, so the registry has nothing to file it under."""

    def encode(self, value):
        return b""

    def decode(self, cursor):
        return None

    def detect(self, head):
        return False


class TestRegistration:
    """What ``register_codec`` accepts. A bad codec must fail here, not later."""

    @pytest.fixture(autouse=True)
    def _restore_registry(self):
        saved = known_codecs()
        yield
        _CODECS.clear()
        _CODECS.update(saved)

    def test_a_well_formed_codec_registers(self):
        register_codec(_GoodCodec())
        assert codec_for("good").name == "good"

    def test_a_codec_missing_detect_is_refused(self):
        # Registering it would work and then break every later read() with no
        # format=, on tags this codec has nothing to do with.
        with pytest.raises(TypeError, match="missing detect"):
            register_codec(_NoDetect())
        assert detect_codec(b"SNS1") is None

    def test_a_codec_missing_a_name_is_refused(self):
        with pytest.raises(TypeError, match="missing name"):
            register_codec(_Nameless())

    def test_an_empty_name_is_refused(self):
        codec = _GoodCodec()
        codec.name = ""
        with pytest.raises(TypeError, match="non-empty string"):
            register_codec(codec)

    def test_a_duplicate_name_is_refused(self):
        register_codec(_GoodCodec())
        with pytest.raises(ValueError, match="already registered"):
            register_codec(_GoodCodec())

    def test_a_registered_codec_is_auto_detected(self):
        register_codec(_GoodCodec())
        cursor = cursor_over(b"GOODhello", size=32)
        assert decode_auto(cursor) == "hello"


class TestRegistryAndDispatch:
    def test_both_v1_codecs_are_registered(self):
        assert set(known_codecs()) == {"tlv", "raw"}

    def test_lookup_by_name(self):
        assert codec_for("tlv") is not None

    def test_an_unknown_format_lists_what_is_available(self):
        with pytest.raises(UnknownFormat) as excinfo:
            codec_for("ndef")
        assert "'raw'" in str(excinfo.value)
        assert "'tlv'" in str(excinfo.value)

    def test_auto_decode_finds_the_tlv_payload(self):
        cursor = cursor_over(TLV.encode(["x", 1]), size=64)
        assert decode_auto(cursor) == ["x", 1]

    def test_auto_decode_names_ndef(self):
        cursor = cursor_over(b"\x03\x03\xd0\x00\x00\xfe", size=16)
        with pytest.raises(NdefNotSupported, match="not supported"):
            decode_auto(cursor)

    def test_auto_decode_on_a_blank_tag(self):
        cursor = cursor_over(b"", size=48)
        with pytest.raises(UnknownFormat, match="format='raw'"):
            decode_auto(cursor)

    def test_auto_decode_on_someone_elses_bytes(self):
        cursor = cursor_over(b"cf12ac\x00\x00", size=48)
        with pytest.raises(UnknownFormat) as excinfo:
            decode_auto(cursor)
        assert "63 66 31 32" in str(excinfo.value)
