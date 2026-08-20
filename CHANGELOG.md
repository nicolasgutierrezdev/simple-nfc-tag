# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Exception hierarchy rooted at `NfcError`, split into `ReaderError`, `CardError` and
  `FormatError`. `ApduError` carries both status bytes, a decoded meaning where one is known,
  and the command that produced them.
- `Reader` abstraction: reader handle and card connection have separate lifetimes. The PC/SC
  part-3 pseudo-APDUs (`FF CA`, `FF B0`, `FF D6`, `FF 82`, `FF 86`) are built on the base class,
  so no reader-specific bytes reach card code.
- `PCSCReader`, a generic pyscard-backed driver. pyscard is imported lazily, so the package
  imports and the suite runs with no PC/SC stack present.
- `ACR122U` driver: PN532 passthrough for `transceive`, buzzer and LED control, firmware
  version.
- Reader factory: `connect()` / `open_reader()` pick a driver from the PC/SC reader name and
  fall back to standard PC/SC. `register_reader()` adds third-party drivers.
- Cached-connection tag access: `current_tag()` and `wait_for_tag()`. One RF session and one
  identification per card presence, not per read.
- `FakeReader` with Ultralight, NTAG213/215/216 and Classic 1K/4K images, so every feature is
  testable with no hardware attached.
- `Card` abstraction with a flat linear tier over user memory, plus drivers for MIFARE
  Ultralight, NTAG213/215/216, MIFARE Classic 1K and 4K. Tags are identified from the ATR plus
  `GET_VERSION`, with a page-probing fallback for readers with no passthrough.
- `KeyProvider` for MIFARE Classic keys, with per-sector authentication cached per presence.
- `reset_card_connection()`, for the recovery a tag needs after refusing a command: it stops
  answering until it is reselected.
- Packaging and CI: build, `twine check`, and the suite run against the installed wheel.
- One length rule for the whole wire format, the NFC Forum Type-2 one, used by the outer TLV
  blocks and the typed values inside them. The inner tier was specified as BER (ISO 7816-4) and
  unified before release.
- Codecs: `tlv` (a sequence of auto-typed values in a proprietary Type-2 TLV block) and `raw`
  (bytes verbatim). `tag.write(value)` / `tag.read()` sit on them, with the format detected from
  what is on the tag when none is given.
- Explicit width wrappers `U8`/`U16`/`U32`/`U64` and `I8`/`I16`/`I32`/`I64`, for pinning an
  encoding to match an existing layout.
- `ByteCursor`, so decoding pulls only the bytes a payload needs instead of draining the tag.
- `Monitor`: a background thread reporting tags as they arrive and leave, with a per-UID
  debounce.
- `Reader.wait_for_change()`, which `PCSCReader` implements with `SCardGetStatusChange`, so a
  monitor over an empty reader blocks in the driver instead of waking on a timer.
- `Ultralight.authenticate(password, pack=None)` for NTAG21x `PWD_AUTH`, with optional PACK
  verification. `FakeReader`'s NTAG images model passwords and page protection.
- `examples/roundtrip.py`, the manual hardware check. Read-only unless `--write` is passed.
- `examples/monitor.py`, which streams arrivals and departures live with timestamps.
- `Ultralight.set_password(password, pack, protect_from=None, protect_reads=None)`, which writes
  the password pages and then, once the new password has been proved on a fresh session, `AUTH0`
  (`protect_from`) and `PROT` (`protect_reads`). A factory tag leaves `PROT` clear, so a password
  alone is a tamper lock, not privacy; `protect_reads=True` closes reads. `AUTHLIM` and `CFGLCK`
  are deliberately not exposed: both can brick a tag permanently.
- Write verification, on by default: `write_bytes()` and `write()` take `verify=True` and read
  the payload back, raising `WriteVerificationError` (with the offset, the expected bytes, what
  the tag holds, and the first byte that differs) when it did not land. A refused write is not
  reliably reported: on an NTAG it answers `90 00` and changes nothing. Pass `verify=False` to
  skip the read-back. Costs one read per four pages on an NTAG, one per block on a Classic.
- MIFARE Classic key and access-bit management: `access_bits.py`
  (`encode_access_bits`/`decode_access_bits`/`verify_redundancy` and the transport, read-only and
  dead-block constants), plus `MifareClassic.read_sector_trailer()`, `write_sector_trailer()` and
  `set_sector_keys()`. Trailer writes require
  `i_understand_this_can_brick_the_sector=True`, refuse any access condition that would leave a
  data block dead, and verify the access bytes on a fresh session under the new key A.

### Changed

- Raised the Python floor to 3.10 (`0.0.1` declared 3.9). pyscard publishes no 3.9 wheel for
  Windows, so a 3.9 floor meant Windows users had to compile it.

### Fixed

- MIFARE Classic authentication tracked open sectors as a set, but a Classic holds exactly one
  sector open at a time: opening the next closes the last. Any read spanning more than one sector
  failed with `63 00` from the second sector onwards. Now caches the single open sector.
- `FakeReader`'s Classic image now matches measured hardware: one open sector at a time, `63 00`
  rather than `69 82` for an unauthenticated read, no deselect on a refused key, and key A
  reading back as zeros.

### Planned

- An NDEF codec, as an additive change
- The release workflow and the first tagged release

## [0.0.1] - 2026-08-18

- Placeholder release reserving the project name. No functionality.
