"""Inner values: the type registry and how each type is encoded.

One byte of type id, then a length, then the value. Lengths use the single rule in
:mod:`~simple_nfc_tag.codecs.framing` -- the same one the outer TLV stream uses -- so
there is exactly one length convention in this file format rather than one per tier.

The type ids below are public API. After v1.0 they are frozen: a new type takes an
unused id, and an existing id never changes meaning, because tags written by an older
version keep working.
"""

from __future__ import annotations

import json
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar

from simple_nfc_tag.exceptions import DecodeError

__all__ = [
    "BOOL",
    "BYTES",
    "CALLER_TYPE_IDS",
    "FLOAT",
    "I8",
    "I16",
    "I32",
    "I64",
    "INT",
    "JSON",
    "STR",
    "U8",
    "U16",
    "U32",
    "U64",
    "UINT",
    "decode_value",
    "encode_value",
    "known_types",
    "register_type",
]

# Inner type ids. Frozen from v1.0 onwards.
STR = 0x01
UINT = 0x02
INT = 0x03
BYTES = 0x04
BOOL = 0x05
FLOAT = 0x06
JSON = 0x07

#: Ids callers may register their own types in. Everything below is reserved so this
#: package can add types later without colliding with anyone.
CALLER_TYPE_IDS = range(0x10, 0x80)


# ----------------------------------------------------------- fixed-width ints


class _Fixed(int):
    """An int that remembers how many bytes it should occupy on the tag."""

    width: ClassVar[int] = 0
    signed: ClassVar[bool] = False

    def __repr__(self) -> str:
        return f"{type(self).__name__}({int(self)})"


class U8(_Fixed):
    """An unsigned int pinned to one byte on the tag."""

    width = 1


class U16(_Fixed):
    """An unsigned int pinned to two bytes on the tag.

    Worth knowing about when porting an existing layout: values are normally stored in
    the fewest bytes that fit, so a plain ``42`` occupies one byte, not two.
    """

    width = 2


class U32(_Fixed):
    """An unsigned int pinned to four bytes on the tag."""

    width = 4


class U64(_Fixed):
    """An unsigned int pinned to eight bytes on the tag."""

    width = 8


class I8(_Fixed):
    """A signed int pinned to one byte on the tag."""

    width = 1
    signed = True


class I16(_Fixed):
    """A signed int pinned to two bytes on the tag."""

    width = 2
    signed = True


class I32(_Fixed):
    """A signed int pinned to four bytes on the tag."""

    width = 4
    signed = True


class I64(_Fixed):
    """A signed int pinned to eight bytes on the tag."""

    width = 8
    signed = True


# ------------------------------------------------------------------- registry


@dataclass(frozen=True)
class InnerType:
    """One entry in the inner type registry."""

    id: int
    name: str
    encode: Callable[[Any], bytes]
    decode: Callable[[bytes], Any]
    #: Python types this entry claims when a value is auto-typed. Checked in
    #: registration order, so narrower types must be registered before wider ones --
    #: bool before int, since bool *is* an int.
    claims: tuple[type, ...] = ()


_TYPES: dict[int, InnerType] = {}
_ORDER: list[InnerType] = []


def register_type(
    type_id: int,
    name: str,
    encode: Callable[[Any], bytes],
    decode: Callable[[bytes], Any],
    claims: tuple[type, ...] = (),
) -> InnerType:
    """Add a type to the inner registry.

    Use an id from :data:`CALLER_TYPE_IDS`. Everything below that range belongs to this
    package and may be given a meaning in a later version; taking one now would make
    the tag unreadable by anything but the code that wrote it.
    """
    if type_id in _TYPES:
        raise ValueError(
            f"inner type 0x{type_id:02X} is already registered as {_TYPES[type_id].name}"
        )
    if not 0 <= type_id <= 0xFF:
        raise ValueError(f"inner type id out of range: {type_id}")

    entry = InnerType(type_id, name, encode, decode, claims)
    _TYPES[type_id] = entry
    _ORDER.append(entry)
    return entry


def known_types() -> dict[int, str]:
    """The registered inner types, as ``{id: name}``."""
    return {entry.id: entry.name for entry in _ORDER}


def encode_value(value: Any) -> tuple[int, bytes]:
    """Work out a value's inner type and encode it, returning ``(type id, bytes)``.

    Three cases are decided here rather than by the registry, because the type alone
    does not determine the answer: an explicit width wrapper pins the byte count, a
    bool must be caught before int since it *is* one, and a plain int picks between
    the unsigned and signed encodings by its sign.
    """
    if isinstance(value, _Fixed):
        return (INT if value.signed else UINT), _fixed_bytes(value)
    if isinstance(value, bool):
        return BOOL, _TYPES[BOOL].encode(value)
    if isinstance(value, int):
        return (UINT, _encode_uint(value)) if value >= 0 else (INT, _encode_int(value))

    for entry in _ORDER:
        if entry.claims and isinstance(value, entry.claims):
            return entry.id, entry.encode(value)

    # Anything with no dedicated encoding travels as JSON rather than failing: a dict
    # or a nested list is a reasonable thing to want on a tag.
    return JSON, _TYPES[JSON].encode(value)


def decode_value(type_id: int, payload: bytes) -> Any:
    """Decode one inner value."""
    entry = _TYPES.get(type_id)
    if entry is None:
        raise DecodeError(
            f"unknown inner type 0x{type_id:02X}; known types are "
            + ", ".join(f"0x{i:02X} ({n})" for i, n in sorted(known_types().items()))
        )
    return entry.decode(payload)


# ------------------------------------------------------------------ encodings


def _fixed_bytes(value: _Fixed) -> bytes:
    try:
        return int(value).to_bytes(value.width, "big", signed=value.signed)
    except OverflowError as exc:
        raise ValueError(
            f"{int(value)} does not fit in {type(value).__name__} ({value.width} bytes)"
        ) from exc


def _encode_uint(value: int) -> bytes:
    if value < 0:
        raise ValueError(f"not an unsigned value: {value}")
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _encode_int(value: int) -> bytes:
    width = max(1, (value.bit_length() + 8) // 8)
    while True:
        try:
            return value.to_bytes(width, "big", signed=True)
        except OverflowError:  # pragma: no cover - one extra byte always suffices
            width += 1


def _decode_uint(payload: bytes) -> int:
    if not payload:
        raise DecodeError("an unsigned value needs at least one byte")
    return int.from_bytes(payload, "big")


def _decode_int(payload: bytes) -> int:
    if not payload:
        raise DecodeError("a signed value needs at least one byte")
    return int.from_bytes(payload, "big", signed=True)


def _decode_str(payload: bytes) -> str:
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError(f"string value is not valid UTF-8: {exc}") from exc


def _decode_bool(payload: bytes) -> bool:
    if len(payload) != 1:
        raise DecodeError(f"a boolean is one byte, got {len(payload)}")
    return payload != b"\x00"


def _decode_float(payload: bytes) -> float:
    if len(payload) != 8:
        raise DecodeError(f"a float is eight bytes, got {len(payload)}")
    return float(struct.unpack(">d", payload)[0])


def _decode_json(payload: bytes) -> Any:
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"JSON value could not be parsed: {exc}") from exc


# Registration order matters to the claim scan in encode_value: a narrower type has to
# be registered before a wider one. The numeric types claim nothing, because which of
# them applies is decided by sign and by width wrappers rather than by Python type.
register_type(BOOL, "bool", lambda v: b"\x01" if v else b"\x00", _decode_bool)
register_type(STR, "str", lambda v: v.encode("utf-8"), _decode_str, (str,))
register_type(BYTES, "bytes", bytes, lambda p: bytes(p), (bytes, bytearray))
register_type(FLOAT, "float64", lambda v: struct.pack(">d", v), _decode_float, (float,))
register_type(JSON, "json", lambda v: json.dumps(v, separators=(",", ":")).encode(), _decode_json)
register_type(UINT, "uint", _encode_uint, _decode_uint)
register_type(INT, "int", _encode_int, _decode_int)
