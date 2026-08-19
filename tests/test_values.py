"""Inner values: the type registry and each type's encoding.

Lengths are not tested here -- there is only one length rule in this file format and
it lives with the framing, in test_codecs.py.
"""

from __future__ import annotations

import math

import pytest

from simple_nfc_tag.codecs import values
from simple_nfc_tag.codecs.values import (
    I8,
    I16,
    U8,
    U16,
    U32,
    U64,
    decode_value,
    encode_value,
)
from simple_nfc_tag.exceptions import DecodeError


class TestValues:
    @pytest.mark.parametrize(
        "value",
        [
            "",
            "ABC123",
            "unicode: áéí 中文 \U0001f600",
            b"",
            b"\x00\xff",
            0,
            1,
            42,
            255,
            256,
            65535,
            2**64,
            -1,
            -128,
            -129,
            -(2**40),
            True,
            False,
            3.14159,
            -0.0,
            1e308,
        ],
    )
    def test_round_trip(self, value):
        type_id, payload = encode_value(value)
        decoded = decode_value(type_id, payload)
        assert decoded == value
        assert type(decoded) is type(value)

    def test_special_floats(self):
        type_id, payload = encode_value(math.inf)
        assert decode_value(type_id, payload) == math.inf
        type_id, payload = encode_value(math.nan)
        assert math.isnan(decode_value(type_id, payload))

    def test_bool_is_not_stored_as_an_int(self):
        # bool is a subclass of int in Python; storing True as 1 would come back as 1.
        assert encode_value(True)[0] == values.BOOL
        assert encode_value(1)[0] == values.UINT

    def test_negative_ints_use_the_signed_type(self):
        assert encode_value(-1)[0] == values.INT
        assert encode_value(1)[0] == values.UINT

    def test_uints_are_stored_in_the_fewest_bytes(self):
        assert encode_value(42)[1] == b"\x2a"
        assert encode_value(255)[1] == b"\xff"
        assert encode_value(256)[1] == b"\x01\x00"

    def test_zero_still_takes_a_byte(self):
        assert encode_value(0)[1] == b"\x00"

    def test_bytearray_comes_back_as_bytes(self):
        type_id, payload = encode_value(bytearray(b"abc"))
        assert type_id == values.BYTES
        assert decode_value(type_id, payload) == b"abc"

    @pytest.mark.parametrize("value", [{"a": 1}, [1, 2, 3], None, {"nested": {"x": [1, None]}}])
    def test_structures_travel_as_json(self, value):
        type_id, payload = encode_value(value)
        assert type_id == values.JSON
        assert decode_value(type_id, payload) == value


class TestFixedWidth:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (U8(42), "2A"),
            (U16(42), "002A"),
            (U32(42), "0000002A"),
            (U64(42), "000000000000002A"),
            (I8(-1), "FF"),
            (I16(-2), "FFFE"),
        ],
    )
    def test_width_is_pinned(self, value, expected):
        assert encode_value(value)[1].hex().upper() == expected

    def test_a_fixed_width_value_is_still_an_int(self):
        assert U16(42) == 42
        assert U16(42) + 1 == 43

    def test_signed_wrappers_use_the_signed_type(self):
        assert encode_value(I16(-2))[0] == values.INT
        assert encode_value(U16(2))[0] == values.UINT

    def test_a_value_too_big_for_its_width_is_refused(self):
        with pytest.raises(ValueError, match="does not fit"):
            encode_value(U8(256))

    def test_repr_names_the_wrapper(self):
        assert repr(U16(42)) == "U16(42)"


class TestErrors:
    def test_an_unknown_type_id_lists_the_known_ones(self):
        with pytest.raises(DecodeError) as excinfo:
            decode_value(0x7E, b"")
        assert "0x7E" in str(excinfo.value)
        assert "uint" in str(excinfo.value)

    def test_a_truncated_number(self):
        with pytest.raises(DecodeError, match="at least one byte"):
            decode_value(values.UINT, b"")

    def test_a_bad_boolean_width(self):
        with pytest.raises(DecodeError, match="one byte"):
            decode_value(values.BOOL, b"\x00\x01")

    def test_a_bad_float_width(self):
        with pytest.raises(DecodeError, match="eight bytes"):
            decode_value(values.FLOAT, b"\x00")

    def test_invalid_utf8(self):
        with pytest.raises(DecodeError, match="UTF-8"):
            decode_value(values.STR, b"\xff\xfe")

    def test_invalid_json(self):
        with pytest.raises(DecodeError, match="JSON"):
            decode_value(values.JSON, b"{not json")


class TestRegistry:
    def test_registering_over_an_existing_id_is_refused(self):
        with pytest.raises(ValueError, match="already registered"):
            values.register_type(values.STR, "mine", bytes, bytes)

    def test_a_caller_type_round_trips(self):
        type_id = 0x40
        values.register_type(type_id, "reversed", lambda v: v[::-1], lambda p: p[::-1])
        try:
            assert decode_value(type_id, b"abc") == b"cba"
            assert type_id in values.known_types()
        finally:
            del values._TYPES[type_id]
            values._ORDER[:] = [e for e in values._ORDER if e.id != type_id]
