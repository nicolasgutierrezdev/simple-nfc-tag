# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Exception hierarchy rooted at `NfcError`, split into `ReaderError`, `CardError` and
  `FormatError`. `ApduError` carries both status bytes, a decoded meaning where one is
  known, and the command that produced them.
- `Reader` abstraction: reader handle and card connection are separate lifetimes, and the
  PC/SC part-3 pseudo-APDUs (`FF CA`, `FF B0`, `FF D6`, `FF 82`, `FF 86`) are built once on
  the base class so no reader-specific bytes reach card code.
- `PCSCReader`, a generic pyscard-backed driver, with pyscard imported lazily so the package
  imports and the test suite runs with no PC/SC stack present.
- `ACR122U` driver: PN532 passthrough for `transceive` (verified against real hardware),
  buzzer and LED control, firmware version.
- Reader factory: `connect()` / `open_reader()` pick a driver from the PC/SC reader name,
  falling back to standard PC/SC. `register_reader()` lets third parties add their own.
- Cached-connection tag access: `current_tag()` and `wait_for_tag()`. One RF session and one
  identification per card *presence*, not per read.
- `FakeReader` with Ultralight, NTAG213/215/216 and Classic 1K/4K images, so every feature is
  testable with no hardware attached.
- `Card` abstraction with a flat linear tier over user memory, and drivers for MIFARE
  Ultralight, NTAG213/215/216, MIFARE Classic 1K and 4K. Tags are identified from the ATR plus
  `GET_VERSION`, with a page-probing fallback for readers that have no passthrough.
- `KeyProvider` for MIFARE Classic keys, with per-sector authentication cached per presence.
- `reset_card_connection()`, and the recovery it exists for: a tag that refuses a command stops
  answering entirely until it is reselected.
- Packaging and CI: build, `twine check`, and the suite run against the installed wheel.
- One length rule for the whole wire format, the NFC Forum Type-2 one, used by the outer TLV
  blocks and the typed values inside them alike. The inner tier was specified as BER
  (ISO 7816-4) and unified before release: BER costs a byte more for values 128-254 bytes long,
  and a second convention in one format is a standing invitation to apply the wrong one.
- Codecs: `tlv` (a sequence of auto-typed values in a proprietary Type-2 TLV block) and `raw`
  (bytes verbatim). `tag.write(value)` / `tag.read()` sit on them, with the format detected from
  what is on the tag when none is given.
- Explicit width wrappers `U8`/`U16`/`U32`/`U64` and `I8`/`I16`/`I32`/`I64`, for pinning an
  encoding when a layout has to match one that already exists.
- `ByteCursor`, so decoding pulls only the bytes a payload needs instead of draining the tag.
- `Monitor`: a background thread reporting tags as they arrive and leave, with a per-UID
  debounce so a tag parked on the reader is not reported on every tick.
- `Reader.wait_for_change()`, which `PCSCReader` implements with `SCardGetStatusChange` so a
  monitor over an empty reader blocks in the driver instead of waking on a timer.
- `Ultralight.authenticate(password, pack=None)` for NTAG21x `PWD_AUTH`, with optional PACK
  verification. `FakeReader`'s NTAG images model passwords and page protection.
- `examples/roundtrip.py`, the manual hardware check. Read-only unless `--write` is passed.
- `examples/monitor.py`, which streams arrivals and departures live with timestamps.
- `Ultralight.set_password(password, pack, protect_from=None, protect_reads=None)`, which
  writes the password pages and then, only once the new password has been proved on a fresh
  session, the two settings that decide what protection means: `AUTH0` (`protect_from`) for
  where it starts and `PROT` (`protect_reads`) for whether it covers reads as well as writes.
  A factory tag leaves `PROT` clear, so a password alone is a tamper lock and not privacy;
  `protect_reads=True` is what closes reads. `AUTHLIM` and `CFGLCK` are deliberately not
  exposed -- both can brick a tag permanently.
- Write verification, on by default: `write_bytes()` and `write()` take `verify=True` and read
  the payload back to confirm it landed, raising `WriteVerificationError` (with the offset, the
  expected bytes, what the tag holds, and the first byte that differs) when it did not. A
  refused write is not reliably reported -- on an NTAG it answers `90 00` and changes nothing --
  so this is the only thing standing between a refused write and a silent success. Pass
  `verify=False` to skip the read-back. Costs one read per four pages on an NTAG, one per block
  on a Classic.

### Changed

- Raised the Python floor to 3.10 (`0.0.1` declared 3.9). pyscard publishes no 3.9 wheel for
  Windows, so a 3.9 floor meant Windows users -- most ACR122U users -- had to compile it.

### Fixed

- MIFARE Classic authentication tracked open sectors as a set, but a Classic holds exactly one
  sector open at a time — opening the next closes the last. Any read spanning more than one
  sector failed with `63 00` on the second sector onwards. Now caches the single open sector.
- `FakeReader`'s Classic image now matches measured hardware: one open sector at a time, `63 00`
  rather than `69 82` for an unauthenticated read, no deselect on a refused key, and key A
  reading back as zeros.

### Still to come

- An NDEF codec, as an additive change rather than a rewrite
- The release workflow and the first tagged release

## [0.0.1] - 2026-08-18

- Placeholder release reserving the project name. No functionality.
