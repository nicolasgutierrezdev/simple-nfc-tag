"""An in-memory reader, for tests and for trying the library without hardware.

This is a real part of the package, not a test fixture: every feature has to be
usable without a reader attached, and that promise is only worth anything if the
fake behaves like the silicon does. So the tag images here reproduce the parts that
actually bite --

* an Ultralight read returns 16 bytes (four pages) however many you wanted, and
  **wraps around** to page 0 at the end of memory;
* reading past the last page answers ``63 00``, which is what an ACR122U reports and
  is *not* the ``6A 82`` you might expect;
* a plain Ultralight has no ``GET_VERSION``, so asking for one fails, exactly as it
  does on a real one -- which is what makes the identification fallback testable;
* a Classic block cannot be read until its sector has been authenticated, only **one**
  sector is open at a time, and any authentication attempt -- successful or not --
  closes the one before it;
* and, the one that is easiest to miss: **a refused command deselects the tag**. Once
  a tag has answered anything other than 90 00, it answers nothing at all -- a plain
  retry of a perfectly valid read still fails -- until a ``GET UID`` re-runs
  anticollision and brings it back. Code that probes, for the end of memory or for a
  working key, has to recover after each failure, and modelling that here is what
  makes the omission fail in a test rather than on someone's desk.

Both behaviours above were captured from an ACR122U with an NTAG213 on it.
"""

from __future__ import annotations

from typing import ClassVar

from simple_nfc_tag.exceptions import ApduError, NoCardPresent, ReaderNotSupported
from simple_nfc_tag.keys import FACTORY_KEY, KeyType
from simple_nfc_tag.readers.base import Reader

#: Raw ISO 14443-3 commands the NTAG images answer.
GET_VERSION = bytes([0x60])
PWD_AUTH = bytes([0x1B])
READ = bytes([0x30])

__all__ = [
    "GET_VERSION",
    "PWD_AUTH",
    "READ",
    "FakeClassic1K",
    "FakeClassic4K",
    "FakeNTAG213",
    "FakeNTAG215",
    "FakeNTAG216",
    "FakeReader",
    "FakeTag",
    "FakeUltralight",
]


def _atr_for(card_name: int) -> bytes:
    """Build the PC/SC contactless ATR a reader synthesises for a storage card."""
    body = bytearray(bytes.fromhex("3B8F8001804F0CA0000003060300000000000000"))
    body[13:15] = card_name.to_bytes(2, "big")
    checksum = 0
    for byte in body[1:-1]:
        checksum ^= byte
    body[-1] = checksum
    return bytes(body)


class _StatusWord(Exception):
    """Raised inside a tag image to answer with a status word other than 90 00.

    ``deselects`` says whether the refusal also drops the tag out of the RF session,
    which is not the same question as which status word came back. Measured on an
    ACR122U: an NTAG read past the end of memory deselects, while a Classic refusing
    an unauthorised read or a wrong key does not -- and both answer ``63 00``.
    """

    def __init__(self, sw1: int, sw2: int, deselects: bool = True) -> None:
        super().__init__(f"{sw1:02X}{sw2:02X}")
        self.sw1 = sw1
        self.sw2 = sw2
        self.deselects = deselects


class _SilentDrop(Exception):
    """Raised inside a tag image for a write that is refused but reported as success.

    Measured on an ACR122U with an NTAG213: a write to a page protected by ``AUTH0``
    answers ``90 00`` and the page keeps its previous contents. The NAK does reach the
    reader -- the tag deselects, so the *next* command answers ``63 00`` -- but ``FF D6``
    never passes the refusal back to the caller. Modelling it here is what makes
    ``verify=`` testable with no hardware on the desk.
    """


def _failed(deselects: bool = True) -> _StatusWord:
    """``63 00``: what an ACR122U reports for almost every refusal."""
    return _StatusWord(0x63, 0x00, deselects)


class FakeTag:
    """An in-memory tag image.

    Concrete on purpose: the default behaviour here is a plain memory array with no
    keys and no vendor commands, which is exactly what an Ultralight is. Subclasses
    add the parts that differ.
    """

    #: PC/SC card name this tag reports in its ATR.
    card_name: ClassVar[int] = 0x0000
    #: Bytes per natively addressed unit.
    block_size: ClassVar[int] = 4
    #: Total addressable units, user and reserved alike.
    block_count: ClassVar[int] = 0

    def __init__(self, uid: bytes = b"\x04\x9a\xee\xe2\x30\x73\x80") -> None:
        self.uid = bytes(uid)
        self.memory = bytearray(self.block_count * self.block_size)
        self.atr = _atr_for(self.card_name)
        #: Every block index written, in order, so tests can assert on wear.
        self.writes: list[int] = []
        self._init_memory()

    def _init_memory(self) -> None:
        """Lay down whatever the tag ships with."""

    # --------------------------------------------------------------- addressing

    def read(self, block: int, length: int) -> bytes:
        """Answer an ``FF B0``."""
        if block >= self.block_count:
            raise _failed()
        end = block * self.block_size + length
        if end <= len(self.memory):
            return bytes(self.memory[block * self.block_size : end])
        # Past the end of memory the tag wraps back to block 0 rather than failing.
        data = bytearray(self.memory[block * self.block_size :])
        while len(data) < length:
            data.extend(self.memory[: length - len(data)])
        return bytes(data[:length])

    def write(self, block: int, data: bytes) -> None:
        """Answer an ``FF D6``."""
        if block >= self.block_count or len(data) != self.block_size:
            raise _failed()
        self.writes.append(block)
        start = block * self.block_size
        self.memory[start : start + len(data)] = data

    def command(self, payload: bytes) -> bytes:
        """Answer a raw ISO 14443-3 command sent through :meth:`Reader.transceive`."""
        raise _failed()

    def load_key(self, slot: int, key: bytes) -> None:
        """Answer an ``FF 82``. Only tags with sector keys care."""

    def authenticate(self, block: int, key_type: KeyType, slot: int) -> None:
        """Answer an ``FF 86``. Only tags with sector keys care."""


class FakeUltralight(FakeTag):
    """A MIFARE Ultralight: 16 pages, 48 bytes of user memory, no GET_VERSION."""

    card_name = 0x0003
    block_size = 4
    block_count = 16

    def _init_memory(self) -> None:
        # Pages 0-2 carry the UID, its check bytes and the lock bytes.
        self.memory[0:3] = self.uid[0:3]
        self.memory[3] = 0x88 ^ self.uid[0] ^ self.uid[1] ^ self.uid[2]
        self.memory[4:8] = self.uid[3:7]

    def write(self, block: int, data: bytes) -> None:
        if block < 2:
            # The UID pages are read-only on real silicon.
            raise _failed()
        super().write(block, data)


class _NTAG(FakeUltralight):
    """An NTAG21x: an Ultralight that answers GET_VERSION and can hold a password."""

    #: The eight bytes GET_VERSION returns; byte 6 is the storage size code.
    version: ClassVar[bytes] = b""
    #: Capability-container byte 2, which is user memory / 8.
    cc_size: ClassVar[int] = 0

    def __init__(
        self,
        uid: bytes = b"\x04\x9a\xee\xe2\x30\x73\x80",
        password: bytes | None = None,
        pack: bytes = b"\x00\x00",
        protect_from: int | None = None,
        protect_reads: bool = False,
    ) -> None:
        #: The password. Held apart from ``memory`` because its page is write-only.
        self.password = bytes(password) if password is not None else None
        self.pack = bytes(pack)
        self._initial_auth0 = 0xFF if protect_from is None else protect_from
        self._initial_prot = protect_reads
        #: Whether PWD_AUTH has been passed during this RF session.
        self.authenticated = False
        super().__init__(uid)

    @property
    def config_page(self) -> int:
        """CFG0. The four configuration pages are the last four on the tag."""
        return self.block_count - 4

    def _init_memory(self) -> None:
        super()._init_memory()
        self.memory[12:16] = bytes([0xE1, 0x11, self.cc_size, 0x00])

        base = self.config_page * self.block_size
        # CFG0: mirror byte, two RFUI, AUTH0. CFG1: ACCESS, then RFUI.
        self.memory[base : base + 4] = bytes([0x04, 0x00, 0x00, self._initial_auth0])
        self.memory[base + 4 : base + 8] = bytes(
            [0x80 if self._initial_prot else 0x00, 0x05, 0x00, 0x00]
        )

    @property
    def protect_from(self) -> int | None:
        """First protected page, from AUTH0. ``None`` when protection is disabled."""
        auth0 = self.memory[self.config_page * self.block_size + 3]
        return None if auth0 == 0xFF else auth0

    @property
    def protect_reads(self) -> bool:
        """The PROT bit. False means protection covers writes only."""
        return bool(self.memory[(self.config_page + 1) * self.block_size] & 0x80)

    def command(self, payload: bytes) -> bytes:
        if payload[:1] == GET_VERSION:
            return self.version
        if payload[:1] == PWD_AUTH and len(payload) == 5:
            if self.password is None or payload[1:] != self.password:
                # A refused password is NAKed, and that drops the tag out of the
                # session -- the same rule as any other refusal.
                raise _failed()
            self.authenticated = True
            return self.pack
        if payload[:1] == READ and len(payload) == 2:
            return self.read(payload[1], 16)
        raise _failed()

    def read(self, block: int, length: int) -> bytes:
        if self.protect_reads:
            self._require_password(block)
        data = bytearray(super().read(block, length))

        # The password and its PACK answer as zeros however they were set: they are
        # write-only, which is why nothing can back a password up off a tag.
        for index, page in enumerate(range(block, block + length // self.block_size)):
            if page in (self.config_page + 2, self.config_page + 3):
                start = index * self.block_size
                data[start : start + self.block_size] = bytes(self.block_size)
        return bytes(data)

    def write(self, block: int, data: bytes) -> None:
        # Reads of a protected page are refused out loud; writes are not. See
        # _SilentDrop -- this asymmetry is the reason verify= exists.
        if self._is_protected(block):
            raise _SilentDrop

        if block == self.config_page + 2:
            self.password = bytes(data)
            self.writes.append(block)
            return
        if block == self.config_page + 3:
            self.pack = bytes(data[:2])
            self.writes.append(block)
            return
        super().write(block, data)

    def _is_protected(self, block: int) -> bool:
        """Whether this page is currently closed to the caller."""
        protect_from = self.protect_from
        if protect_from is None or self.authenticated:
            return False
        return block >= protect_from

    def _require_password(self, block: int) -> None:
        """Refuse protected pages until PWD_AUTH has been passed."""
        if self._is_protected(block):
            raise _failed()


class FakeNTAG213(_NTAG):
    """NTAG213: 45 pages, 144 bytes of user memory."""

    block_count = 45
    version = bytes.fromhex("0004040201000F03")
    cc_size = 0x12


class FakeNTAG215(_NTAG):
    """NTAG215: 135 pages, 504 bytes of user memory."""

    block_count = 135
    version = bytes.fromhex("0004040201001103")
    cc_size = 0x3E


class FakeNTAG216(_NTAG):
    """NTAG216: 231 pages, 888 bytes of user memory."""

    block_count = 231
    version = bytes.fromhex("0004040201001303")
    cc_size = 0x6D


class FakeClassic1K(FakeTag):
    """A MIFARE Classic 1K: 16 sectors of four 16-byte blocks, keyed per sector."""

    card_name = 0x0001
    block_size = 16
    block_count = 64
    blocks_per_sector: ClassVar[int] = 4

    def __init__(
        self,
        uid: bytes = b"\xde\xad\xbe\xef",
        key_a: bytes = FACTORY_KEY,
        key_b: bytes = FACTORY_KEY,
    ) -> None:
        self.key_a = bytes(key_a)
        self.key_b = bytes(key_b)
        super().__init__(uid)
        self._slots: dict[int, bytes] = {}
        #: The single open sector. A Classic authenticates one at a time.
        self._open_sector: int | None = None

    def _init_memory(self) -> None:
        self.memory[0 : len(self.uid)] = self.uid
        for trailer in self._trailers():
            start = trailer * self.block_size
            self.memory[start : start + 6] = self.key_a
            self.memory[start + 6 : start + 10] = b"\xff\x07\x80\x69"
            self.memory[start + 10 : start + 16] = self.key_b

    def _trailers(self) -> range:
        return range(self.blocks_per_sector - 1, self.block_count, self.blocks_per_sector)

    def sector_of(self, block: int) -> int:
        return block // self.blocks_per_sector

    def load_key(self, slot: int, key: bytes) -> None:
        self._slots[slot] = bytes(key)

    def authenticate(self, block: int, key_type: KeyType, slot: int) -> None:
        # Any authentication attempt closes whatever was open, successful or not.
        self._open_sector = None

        key = self._slots.get(slot)
        if key is None:
            raise _failed(deselects=False)
        trailer = (self.sector_of(block) + 1) * self.blocks_per_sector - 1
        start = trailer * self.block_size
        expected = (
            bytes(self.memory[start : start + 6])
            if key_type is KeyType.A
            else bytes(self.memory[start + 10 : start + 16])
        )
        if key != expected:
            raise _failed(deselects=False)
        self._open_sector = self.sector_of(block)

    def read(self, block: int, length: int) -> bytes:
        self._require_auth(block)
        if block * self.block_size + length > len(self.memory):
            raise _failed()
        data = bytearray(super().read(block, length))

        # Key A is never readable. It answers as zeros however the sector is
        # configured, which is what a real trailer read looks like -- anyone checking
        # that a write left the keys alone has to look at the access bits, not at
        # what comes back where key A lives.
        for index, block_number in enumerate(range(block, block + length // self.block_size)):
            if self._is_trailer(block_number):
                start = index * self.block_size
                data[start : start + 6] = bytes(6)
        return bytes(data)

    def _is_trailer(self, block: int) -> bool:
        return block % self.blocks_per_sector == self.blocks_per_sector - 1

    def write(self, block: int, data: bytes) -> None:
        self._require_auth(block)
        super().write(block, data)

    def _require_auth(self, block: int) -> None:
        if block >= self.block_count:
            raise _failed()
        if self.sector_of(block) != self._open_sector:
            # 63 00, not the 69 82 you might expect, and it leaves the tag selected.
            raise _failed(deselects=False)


class FakeClassic4K(FakeClassic1K):
    """A MIFARE Classic 4K, in its simple form: 256 blocks of four per sector.

    Real 4K silicon switches to 16-block sectors above sector 31; the driver knows
    that, and this image is enough to exercise everything below the switch.
    """

    card_name = 0x0002
    block_count = 256


class FakeReader(Reader):
    """A reader with tag images instead of radio.

    >>> reader = FakeReader(FakeNTAG213())
    >>> reader.connect().get_uid().hex()
    '049aeee2307380'

    Presence is under the test's control: :meth:`present` puts a tag in the field and
    :meth:`remove` takes it away, so a timeline of taps can be scripted exactly.
    """

    def __init__(
        self,
        tag: FakeTag | None = None,
        name: str = "Fake PC/SC Reader 0",
        supports_transceive: bool = True,
    ) -> None:
        super().__init__(name)
        self.tag = tag
        #: Set False to model a plain PC/SC reader with no raw passthrough, which is
        #: what forces identification down its fallback path.
        self.supports_transceive = supports_transceive
        #: Every APDU the reader was handed, in order.
        self.sent: list[bytes] = []
        #: How many card connections have been opened over this reader's life.
        self.connections_opened = 0
        self.buzzer: bool | None = None
        self.led: tuple[bool, bool] | None = None
        self._selected = True
        #: How many times a deselected tag had to be brought back.
        self.resets = 0

    # ------------------------------------------------------------ test control

    def present(self, tag: FakeTag) -> FakeTag:
        """Put a tag in the field, replacing whatever was there."""
        self.drop_card_connection()
        self.tag = tag
        return tag

    def remove(self) -> None:
        """Empty the field."""
        self.drop_card_connection()
        self.tag = None

    # ------------------------------------------------------------------- hooks

    def _acquire_reader(self) -> None:
        """Nothing to acquire: there is no driver behind this reader."""

    def _release_reader(self) -> None:
        """Nothing to release."""

    def _open_card(self) -> bool:
        if self.tag is None:
            return False
        self._selected = True
        # A new RF session forgets everything the tag was told: an NTAG password and
        # a Classic's open sector both last exactly one presence.
        if isinstance(self.tag, _NTAG):
            self.tag.authenticated = False
        self.connections_opened += 1
        return True

    def _close_card(self) -> None:
        """No RF session to tear down."""

    def _get_atr(self) -> bytes:
        if self.tag is None:
            return b""
        return self.tag.atr

    def transceive(self, payload: bytes) -> bytes:
        """Hand a raw command to the tag image.

        Implemented rather than raising, because the fake stands in for a reader that
        *does* have a passthrough; a tag that cannot answer the command still refuses
        it, which is the interesting case.
        """
        if not self.supports_transceive:
            raise ReaderNotSupported(f"{self.name} has no ISO 14443-3 passthrough")
        if self.tag is None:
            raise NoCardPresent("no tag on the reader")
        if not self._selected:
            raise ApduError(0x63, 0x00, bytes(payload))
        try:
            return self.tag.command(bytes(payload))
        except _StatusWord as status:
            self._selected = not status.deselects
            raise ApduError(status.sw1, status.sw2, bytes(payload)) from None

    def set_buzzer(self, enabled: bool) -> None:
        self.buzzer = enabled

    def set_led(self, red: bool = False, green: bool = False) -> None:
        self.led = (red, green)

    # -------------------------------------------------------------------- APDU

    def _transmit_raw(self, apdu: bytes) -> tuple[bytes, int, int]:
        self.sent.append(bytes(apdu))
        tag = self.tag
        if tag is None:
            return b"", 0x6A, 0x82

        header, body = apdu[:5], apdu[5:]

        # GET UID re-runs anticollision, which is what brings a deselected tag back;
        # LOAD KEY never touches the radio at all. Everything else needs the tag.
        if not self._selected and header[:2] not in (
            bytes([0xFF, 0xCA]),
            bytes([0xFF, 0x82]),
        ):
            return b"", 0x63, 0x00
        try:
            if header[:4] == bytes([0xFF, 0xCA, 0x00, 0x00]):
                if not self._selected:
                    self._selected = True
                    self.resets += 1
                return tag.uid, 0x90, 0x00
            if header[:3] == bytes([0xFF, 0xB0, 0x00]) and not body:
                return tag.read(header[3], header[4]), 0x90, 0x00
            if header[:3] == bytes([0xFF, 0xD6, 0x00]) and len(body) == header[4]:
                tag.write(header[3], body)
                return b"", 0x90, 0x00
            if header[:3] == bytes([0xFF, 0x82, 0x00]) and len(body) == header[4]:
                tag.load_key(header[3], body)
                return b"", 0x90, 0x00
            if header == bytes([0xFF, 0x86, 0x00, 0x00, 0x05]) and len(body) == 5:
                tag.authenticate(body[2], KeyType(body[3]), body[4])
                return b"", 0x90, 0x00
        except _SilentDrop:
            # The whole point: a refusal the reader reports as success. The tag still
            # deselects, which is the only trace left for anyone who looks.
            self._selected = False
            return b"", 0x90, 0x00
        except _StatusWord as status:
            self._selected = not status.deselects
            return b"", status.sw1, status.sw2

        # Anything else is a command this fake does not model.
        return b"", 0x6D, 0x00
