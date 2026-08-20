# simple-nfc-tag

![simple-nfc-tag banner](https://raw.githubusercontent.com/nicolasgutierrezdev/simple-nfc-tag/main/assets/banner.svg)

*A tag-agnostic NFC data storage library built on PC/SC, abstracting away reader, tag and
protocol details.*

[![CI](https://github.com/nicolasgutierrezdev/simple-nfc-tag/actions/workflows/ci.yml/badge.svg)](https://github.com/nicolasgutierrezdev/simple-nfc-tag/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/simple-nfc-tag.svg)](https://pypi.org/project/simple-nfc-tag/)
[![Python versions](https://img.shields.io/pypi/pyversions/simple-nfc-tag.svg)](https://pypi.org/project/simple-nfc-tag/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **This package is still experimental.** Read and write are verified against real hardware
> (ACR122U, NTAG213, MIFARE Classic 1K), but the API and the data layout written to tags can
> still change between releases.

## Install

```bash
uv add simple-nfc-tag
```

```bash
pip install simple-nfc-tag
```

Python 3.10+. Depends on `pyscard`. No driver swap: uses the PC/SC stack already present on
Windows and macOS, and `pcscd` on Linux.

## Usage

```python
import simple_nfc_tag as snt

with snt.connect() as reader:
    tag = reader.wait_for_tag(timeout=5)
    print(tag.uid.hex(), tag.product, tag.user_size)

    tag.write(["ABC123", 42])   # values in
    print(tag.read())           # -> ["ABC123", 42]
```

Same code against a Classic 1K and an NTAG216. Sector trailers, page-granularity
read-modify-write, Classic authentication and payload framing are handled internally.

Values are typed automatically: `str`, `int`, `float`, `bool`, `bytes`, anything else as JSON.
`read()` with no `format=` detects what is on the tag.

## Features

- **Readers**: generic PC/SC, ACR122U (buzzer, LED, PN532 passthrough), in-memory fake
- **Tags**: MIFARE Classic 1K/4K, Ultralight, NTAG213/215/216, identified automatically
- **Formats**: compact TLV of typed values, and raw bytes
- **Auth**: MIFARE Classic keys and trailers, NTAG21x `PWD_AUTH` and password setting
- **Monitor**: background thread with per-UID debounce, blocking in the PC/SC driver
- **Write verification**: on by default; a refused write reports `SW=9000` on an NTAG
- **Typed**: `py.typed`, no bare `except`, every non-`90 00` answer raises `ApduError`

## vs nfcpy

| | simple-nfc-tag | [nfcpy](https://nfcpy.readthedocs.io/en/latest/overview.html#supported-devices) |
|---|---|---|
| Transport | PC/SC | libusb or serial, direct to the chip |
| Readers | any PC/SC reader | a fixed device list: PN531/PN532/PN533, RC-S956, Port100 |
| ACR122U | primary target, verified | supported, but "it is not recommended to buy this device for use with *nfcpy*" |
| Tags | MIFARE Classic 1K/4K, Ultralight, NTAG213/215/216 | NFC Forum Type 1-4 |
| API level | values (`write([...])` / `read()`) | NDEF records, protocol operations |
| Tag differences | hidden | exposed per tag type |
| Scope | storage on tags | + peer-to-peer, card emulation, connection handover |

Use nfcpy for NFC protocol work. Use this to store data.

## Testing without hardware

```python
from simple_nfc_tag.readers.fake import FakeReader, FakeNTAG213

reader = FakeReader(FakeNTAG213())
tag = reader.wait_for_tag()
tag.write(["ABC123", 42])
assert tag.read() == ["ABC123", 42]
```

The images reproduce the awkward parts: 4-page reads that wrap at end of memory, `63 00` past
the last page, Classic sectors silent until authenticated, and a tag that stops answering after
refusing a command.

## Docs

- [USAGE.md](https://github.com/nicolasgutierrezdev/simple-nfc-tag/blob/main/docs/USAGE.md):
  monitors, Classic keys and trailers, NTAG passwords, raw bytes, custom codecs, errors
- [examples/](https://github.com/nicolasgutierrezdev/simple-nfc-tag/tree/main/examples):
  `roundtrip.py` (manual hardware check), `monitor.py`, `classic_keys.py`

## License

MIT
