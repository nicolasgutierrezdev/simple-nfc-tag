# Usage

Complex usage. The basics are in [../README.md](../README.md).

## Readers

```python
import simple_nfc_tag as snt

snt.list_readers()              # -> ['ACS ACR122U PICC Interface 0', ...]
reader = snt.connect()          # first reader attached
reader = snt.connect("ACR122")  # substring of the PC/SC name
```

The driver is picked from the reader name; anything unrecognised falls back to generic PC/SC.
`connect()` acquires the reader handle only. No tag required.

```python
from simple_nfc_tag.readers import register_reader   # third-party drivers
```

### ACR122U extras

```python
reader.set_buzzer(False)
reader.set_led(red=False, green=True)
reader.firmware_version()          # 'ACR122U207'
reader.transceive(b"\x60")         # raw ISO 14443-3, GET_VERSION
```

## Tag access

```python
tag = reader.current_tag()                    # None if the field is empty
tag = reader.wait_for_tag(timeout=5)          # None on timeout
reader.wait_for_change(timeout=5)             # blocks in the PC/SC driver
```

One RF session and one identification per card presence. The connection dies when the tag
leaves; the next call opens a new one.

```python
tag.uid          # bytes
tag.product      # 'NTAG213', 'MIFARE Classic 1K', ...
tag.user_size    # usable bytes, trailers and reserved pages already excluded
```

## Values

```python
tag.write(["ABC123", 42, 3.14, True, b"\x00\xff", {"any": "json"}])
tag.read()
```

Types are chosen automatically. Ints use the minimal width, so pin it when porting an existing
layout:

```python
from simple_nfc_tag import U16
tag.write(["ABC123", U16(42)])       # 2 bytes, not 1
```

`U8`/`U16`/`U32`/`U64` and `I8`/`I16`/`I32`/`I64`.

### Detection

`read()` with no `format=` looks at the first bytes: a `0xFD` proprietary TLV decodes as `tlv`,
an NDEF message raises `NdefNotSupported`, anything else `UnknownFormat`. Decoding is lazy: it
fetches only the bytes the payload declares, not the whole tag.

### Raw bytes

`raw` is not self-describing, so it must be named both ways.

```python
tag.write(b"\x01\x02\x03", format="raw")
tag.read(format="raw")                  # -> all user_size bytes
```

### Linear memory

Below the codecs, user memory is a flat byte range. Byte 0 is the first byte you own, whatever
its physical address.

```python
tag.read_bytes(offset=0, length=16)
tag.write_bytes(4, b"\xde\xad\xbe\xef")   # read-modify-write when unaligned
```

### Write verification

On by default. `write()` and `write_bytes()` read the payload back and raise
`WriteVerificationError` (offset, expected, actual, first differing byte) when it did not land.
Needed because a refused write answers `SW=9000` on an NTAG.

```python
tag.write(value, verify=False)   # skip the read-back
```

Cost: one read per four pages on an NTAG, one per block on a Classic.

## Monitor

```python
import simple_nfc_tag as snt

def on_tag(tag):
    print(tag.uid.hex(), tag.read())

with snt.connect() as reader:
    with snt.Monitor(reader, on_tag=on_tag, on_removed=print, debounce=2.0) as monitor:
        input("enter to stop")
```

- `debounce`: seconds before the same UID is reported again; `0` reports every tick
- `on_error(NfcError)`: without it, polling errors are swallowed
- `monitor.forget(uid=None)`: clear the debounce for one UID or all
- `poll_interval`: with presence notification, only an upper bound on `stop()` latency

Blocks inside the PC/SC driver, so an empty reader costs nothing and a tap is noticed in
milliseconds.

## MIFARE Classic keys

Factory and well-known keys are tried by default, key A then key B, per sector, cached per
presence.

```python
from simple_nfc_tag import KeyType, StaticKeyProvider

tag.keys = StaticKeyProvider(key=bytes.fromhex("D3F7D3F7D3F7"), key_type=KeyType.A)
tag.keys = StaticKeyProvider(
    key=bytes.fromhex("FFFFFFFFFFFF"),          # fallback for every sector
    per_sector={1: bytes.fromhex("A0A1A2A3A4A5")},
)
```

Custom logic subclasses `KeyProvider` and yields `(KeyType, key)` from `keys_for(sector)`.
`AuthenticationError` is raised when nothing opens a sector.

```python
tag.authenticated_sector    # the one sector currently open, or None
tag.sector_count
tag.sector_of(block)
tag.trailer_block(sector)
```

A Classic holds exactly one sector open at a time: opening the next closes the last.

## MIFARE Classic trailers

**A trailer write has no undo.** A wrong key, or an access condition locking a sector behind a
key you do not have, leaves it unopenable forever.

```python
trailer = tag.read_sector_trailer(2)
trailer.access      # ((0,0,0), (0,0,0), (0,0,0), (0,0,1))
trailer.gpb
trailer.key_a       # zeros on real silicon: key A is write-only
```

To check a trailer write landed, look at `access`, never at the keys.

```python
from simple_nfc_tag import TRANSPORT_DATA, READ_ONLY_TRAILER

tag.set_sector_keys(
    15,
    key_a=bytes.fromhex("D3F7D3F7D3F7"),
    key_b=bytes.fromhex("FFFFFFFFFFFF"),
    i_understand_this_can_brick_the_sector=True,
)

tag.write_sector_trailer(
    15,
    key_a, key_b,
    access=(TRANSPORT_DATA, TRANSPORT_DATA, TRANSPORT_DATA, READ_ONLY_TRAILER),
    gpb=0x00,
    i_understand_this_can_brick_the_sector=True,
)
```

Guards:

- Nothing is written without `i_understand_this_can_brick_the_sector=True`.
- An `access` leaving a *data* block readable and writable by no key is refused, flag or not.
- After the write the trailer is re-read on a fresh authentication under the new key A and the
  access bytes compared, raising `WriteVerificationError`.

A *frozen trailer* (keys that can never change again) is allowed: that is normal read-only.
Holding the access bits fixed and moving only the keys is the safe shape of the operation.

### Access bits

```python
from simple_nfc_tag import encode_access_bits, decode_access_bits
from simple_nfc_tag.access_bits import verify_redundancy, data_permissions, trailer_writers
```

Each bit is stored twice, once inverted; silicon rejects a trailer whose copies disagree.
Constants: `TRANSPORT_DATA` `(0,0,0)`, `TRANSPORT_TRAILER` `(0,0,1)`, `READ_ONLY_TRAILER`
`(0,1,1)`, `DEAD_DATA` `(1,1,1)`.

## NTAG21x passwords

Per card presence. A `PWD_AUTH` lasts one RF session and is forgotten on removal.

```python
tag.authenticate(password=bytes.fromhex("DEADBEEF"), pack=bytes.fromhex("A1B2"))
```

```python
tag.set_password(
    password=bytes.fromhex("DEADBEEF"),
    pack=bytes.fromhex("A1B2"),
    protect_from=4,        # AUTH0: first protected page, 0xFF disables
    protect_reads=True,    # PROT: reads too, not just writes
)
```

- The password is **not readable afterwards**; the page answers zeros. Write it down.
- Protection is changed only after the new password is proved on a fresh session.
- `AUTH0` alone protects writes only. A password without `PROT` is a tamper lock, not privacy.
- `AUTHLIM` and `CFGLCK` are deliberately not exposed: both can brick a tag permanently.
- Before testing a *wrong* password, check `AUTHLIM` is 0. A non-zero limit counts failures
  and can lock the tag for good.

## Custom codecs

A codec sees a flat byte stream, never blocks or pages.

```python
from typing import Any
from simple_nfc_tag import register_codec
from simple_nfc_tag.codecs.base import ByteCursor

class MyCodec:
    name = "mine"

    def encode(self, value: Any) -> bytes:
        return b"MY" + value.encode()

    def decode(self, cursor: ByteCursor) -> Any:
        cursor.skip(2)
        return cursor.read_rest().decode()

    def detect(self, head: bytes) -> bool:
        return head.startswith(b"MY")   # False if not self-describing

register_codec(MyCodec())
tag.write("hello", format="mine")
```

`known_codecs()` lists them, `codec_for(name)` looks one up.

- `register_codec()` checks the shape: a codec missing `detect` is refused there rather than
  breaking a later `read()` with no `format=`.
- A payload whose first non-zero byte is `0x03` is claimed as NDEF before any codec is
  consulted, so a custom magic starting with `0x03` can only be read with `format=` named.
- A custom codec writes from byte 0 and replaces the TLV stream. Other NFC software reading
  the tag sees an unrecognised payload, not an NDEF message.

## Errors

```
NfcError
├── ReaderError        NoReaderFound, ReaderNotSupported
├── CardError          NoCardPresent, CardRemoved, UnsupportedCard, AuthenticationError,
│                      CardFull, WriteVerificationError, ApduError
└── FormatError        DecodeError, UnknownFormat, NdefNotSupported
```

Every APDU answering anything but `90 00` raises `ApduError`, carrying `sw1`, `sw2`, `sw`
(16-bit, for comparison), a decoded meaning where one is known, and the command that produced it.

```python
try:
    tag.write(payload)
except snt.CardFull as exc:
    ...
except snt.ApduError as exc:
    print(hex(exc.sw))
```

## Testing without hardware

```python
from simple_nfc_tag.readers.fake import (
    FakeReader, FakeUltralight, FakeNTAG213, FakeNTAG215, FakeNTAG216,
    FakeClassic1K, FakeClassic4K,
)

reader = FakeReader(FakeClassic1K())
tag = reader.wait_for_tag()
tag.write(["ABC123", 42])
assert tag.read() == ["ABC123", 42]
```

The images model the hardware behaviour that breaks naive code:

- Ultralight/NTAG reads return 4 pages and wrap at the end of memory; past the end is `63 00`
- a refused command deselects an NTAG, so it answers `63 00` until `reset_card_connection()`
- Classic sectors answer `63 00` until authenticated, and hold one sector open at a time
- a refused Classic key does not deselect the tag
- Classic key A reads back as zeros
- NTAG passwords and page protection

## Hardware checks

Manual, never in CI.

```powershell
uv run python examples/roundtrip.py            # read-only; --write to write
uv run python examples/monitor.py              # live arrivals and departures
uv run python examples/classic_keys.py         # key survey; --recover N writes
```
