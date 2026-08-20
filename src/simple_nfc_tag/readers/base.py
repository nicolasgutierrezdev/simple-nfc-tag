"""The :class:`Reader` abstraction.

A ``Reader`` owns two handles with different lifetimes:

* the **reader handle** is long-lived: acquired by :meth:`connect`, held for the life
  of the object, released by :meth:`disconnect`.
* the **card connection** is scoped to one card presence: opened when a tag is first
  seen, reused while it stays in the field, dropped when it leaves.

Subclasses implement the six hooks at the bottom of this module and get the whole
PC/SC part-3 pseudo-APDU surface, so no reader-specific bytes appear in card code.
"""

from __future__ import annotations

import abc
import time
from collections.abc import Sequence
from types import TracebackType
from typing import TYPE_CHECKING

from simple_nfc_tag.exceptions import (
    ApduError,
    CardError,
    CardRemoved,
    NoCardPresent,
    ReaderNotSupported,
)
from simple_nfc_tag.keys import KeyType

if TYPE_CHECKING:  # pragma: no cover - typing only
    from simple_nfc_tag.cards.base import Card

__all__ = ["ApduLike", "Reader"]

#: Anything that can be handed to :meth:`Reader.transmit` as a command.
ApduLike = bytes | bytearray | Sequence[int]

_SUCCESS = (0x90, 0x00)


class Reader(abc.ABC):
    """A PC/SC reader.

    Use :func:`simple_nfc_tag.connect` or a concrete driver rather than this class.
    """

    def __init__(self, name: str) -> None:
        self._name = name
        self._reader_open = False
        self._card_open = False
        self._tag: Card | None = None

    def __repr__(self) -> str:
        state = "connected" if self._reader_open else "disconnected"
        return f"<{type(self).__name__} {self._name!r} {state}>"

    @property
    def name(self) -> str:
        """The PC/SC name of the reader, e.g. ``ACS ACR122U PICC Interface 0``."""
        return self._name

    @property
    def is_connected(self) -> bool:
        """Whether the *reader* handle is held. Says nothing about a tag."""
        return self._reader_open

    # ----------------------------------------------------------------- lifecycle

    def connect(self) -> Reader:
        """Acquire the reader handle. No tag needs to be present."""
        if not self._reader_open:
            self._acquire_reader()
            self._reader_open = True
        return self

    def disconnect(self) -> None:
        """Release the card connection, if any, and then the reader handle."""
        self.drop_card_connection()
        if self._reader_open:
            self._release_reader()
            self._reader_open = False

    def __enter__(self) -> Reader:
        return self.connect()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.disconnect()

    def open_card_connection(self) -> bool:
        """Open a card connection if a tag is in the field.

        Returns ``True`` if a connection is now live, ``False`` if the field is
        empty. Idempotent while the same tag stays present.
        """
        if not self._reader_open:
            self.connect()
        if self._card_open:
            return True
        self._card_open = self._open_card()
        return self._card_open

    def drop_card_connection(self) -> None:
        """Tear down the card connection. Safe to call when there is none."""
        self._tag = None
        if self._card_open:
            self._close_card()
            self._card_open = False

    def reset_card_connection(self) -> bool:
        """Re-establish the RF session with the tag in the field, keeping its identity.

        A tag that refuses a command stops answering: after a read past the end of an
        NTAG, or an authentication with the wrong key, every later command returns
        ``63 00``, including a retry of a read that just worked. Code that expects a
        command to fail (probing for the end of memory, trying candidate keys) has to
        recover afterwards.

        Cheapest route first. A ``GET UID`` makes the reader re-run anticollision,
        which is enough on an ACR122U. Only if that fails is the card connection torn
        down and rebuilt, which costs an RF session and a beep.

        Returns ``False`` if the tag is gone. The identified card object is carried
        across; a swapped-in tag is caught by the next :meth:`current_tag` via the UID.
        """
        if self._card_open:
            try:
                self.get_uid()
            except CardError:
                pass
            else:
                return True

        tag = self._tag
        self.drop_card_connection()
        if not self.open_card_connection():
            return False
        self._tag = tag
        return True

    # ---------------------------------------------------------------- tag access

    def current_tag(self) -> Card | None:
        """The tag on the reader right now, or ``None`` if the field is empty.

        Non-blocking. The card connection and the identification behind it are cached
        while the same tag stays present, so a polling loop costs one UID probe per
        call rather than a fresh RF session.
        """
        if self._tag is not None:
            try:
                uid = self.get_uid()
            except (CardRemoved, NoCardPresent, ApduError):
                # The tag is gone; fall through and look for a new one.
                self.drop_card_connection()
            else:
                if uid == self._tag.uid:
                    return self._tag
                # A different tag was swapped in: the cached identification is stale.
                self.drop_card_connection()

        if not self.open_card_connection():
            return None

        self._tag = self._identify_card()
        return self._tag

    def wait_for_tag(self, timeout: float | None = None, poll_interval: float = 0.1) -> Card | None:
        """Block until a tag is presented, and return it. ``None`` on timeout.

        ``timeout=None`` waits indefinitely.
        """
        if poll_interval <= 0:
            raise ValueError(f"poll_interval must be positive: {poll_interval}")

        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            tag = self.current_tag()
            if tag is not None:
                return tag
            if deadline is None:
                time.sleep(poll_interval)
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            time.sleep(min(poll_interval, remaining))

    def wait_for_change(self, timeout: float | None = None) -> bool:
        """Block until the tag presence may have changed, or ``timeout`` elapses.

        Returns ``True`` if something changed, ``False`` if the wait ran out. The
        distinction is advisory; a caller should still look.

        The base implementation sleeps. A driver that can have the operating system
        wake it on a presence change overrides this.
        """
        if timeout:
            time.sleep(timeout)
        return False

    def _identify_card(self) -> Card:
        """Identify the tag on the live connection.

        Imported lazily: ``cards`` is a layer above this one.
        """
        from simple_nfc_tag.cards import identify

        return identify(self)

    @property
    def has_card_connection(self) -> bool:
        """Whether a card connection is currently held."""
        return self._card_open

    # ---------------------------------------------------------------------- APDU

    def transmit(self, apdu: ApduLike) -> bytes:
        """Send an APDU and return its data, requiring a ``90 00`` status word.

        Raises :class:`ApduError` for every other status word.
        """
        command = bytes(apdu)
        data, sw1, sw2 = self.transmit_raw(command)
        if (sw1, sw2) != _SUCCESS:
            raise ApduError(sw1, sw2, command)
        return data

    def transmit_raw(self, apdu: ApduLike) -> tuple[bytes, int, int]:
        """Send an APDU and return ``(data, sw1, sw2)`` without judging the status.

        For commands where a non-``90 00`` answer is information rather than failure:
        probing a page range, trying a candidate key.
        """
        if not self._card_open and not self.open_card_connection():
            raise NoCardPresent("no tag on the reader")
        try:
            return self._transmit_raw(bytes(apdu))
        except CardRemoved:
            # The connection dies the moment the tag leaves.
            self.drop_card_connection()
            raise

    # ------------------------------------------------------- PC/SC pseudo-APDUs

    def get_uid(self) -> bytes:
        """``FF CA 00 00 00``: the tag's UID (4, 7 or 10 bytes).

        Doubles as the liveness probe: the cheapest command that fails once the tag
        has left the field.
        """
        return self.transmit(b"\xff\xca\x00\x00\x00")

    def read_binary(self, block: int, length: int) -> bytes:
        """``FF B0``: read ``length`` bytes starting at ``block``.

        ``block`` is in the tag's unit, not the reader's: a Classic block is 16 bytes,
        an Ultralight page is 4. An Ultralight read returns 16 bytes (four pages)
        regardless.
        """
        _check_block(block)
        _check_length(length)
        command = bytes([0xFF, 0xB0, 0x00, block, length])
        data = self.transmit(command)
        if len(data) != length:
            raise ApduError(0x62, 0x82, command)
        return data

    def update_binary(self, block: int, data: bytes) -> None:
        """``FF D6``: write ``data`` at ``block``.

        Takes exactly one addressable unit's worth of bytes.
        """
        _check_block(block)
        _check_length(len(data))
        self.transmit(bytes([0xFF, 0xD6, 0x00, block, len(data)]) + bytes(data))

    def load_key(self, slot: int, key: bytes) -> None:
        """``FF 82``: load a 6-byte MIFARE key into a volatile reader key slot."""
        if len(key) != 6:
            raise ValueError(f"MIFARE keys are 6 bytes, got {len(key)}")
        _check_slot(slot)
        self.transmit(bytes([0xFF, 0x82, 0x00, slot, 0x06]) + bytes(key))

    def authenticate(self, block: int, key_type: KeyType, slot: int = 0) -> None:
        """``FF 86``: authenticate ``block``'s sector with a previously loaded key.

        Raises :class:`ApduError` on refusal; the Classic driver turns that into
        :class:`AuthenticationError` once every candidate key has been tried.
        """
        _check_block(block)
        _check_slot(slot)
        self.transmit(bytes([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, int(key_type), slot]))

    # ----------------------------------------------------------- reader-specific

    def get_atr(self) -> bytes:
        """The ATR of the tag currently in the field.

        Carries the card-name bytes that identification decodes.
        """
        if not self._card_open and not self.open_card_connection():
            raise NoCardPresent("no tag on the reader")
        return self._get_atr()

    def transceive(self, payload: bytes) -> bytes:
        """Send a raw ISO 14443-3 command to the tag and return its answer.

        PC/SC has no standard form for this, so each driver wraps it in its own vendor
        APDU. Needed for ``GET_VERSION`` (telling NTAG213/215/216 apart) and
        ``PWD_AUTH``. Drivers without a passthrough raise :class:`ReaderNotSupported`;
        callers need a fallback.
        """
        raise ReaderNotSupported(
            f"{type(self).__name__} has no ISO 14443-3 passthrough; raw commands such as "
            "GET_VERSION are unavailable on this reader"
        )

    # ---------------------------------------------------------------- peripherals

    def set_buzzer(self, enabled: bool) -> None:  # noqa: B027 - a no-op is the default
        """Enable or disable the reader's card-detection beep. No-op if unsupported."""

    def set_led(  # noqa: B027 - a no-op is the default
        self, red: bool = False, green: bool = False
    ) -> None:
        """Set the reader's status LEDs. No-op if unsupported."""

    # ---------------------------------------------------------- subclass contract

    @abc.abstractmethod
    def _acquire_reader(self) -> None:
        """Take the long-lived reader handle."""

    @abc.abstractmethod
    def _release_reader(self) -> None:
        """Release the reader handle."""

    @abc.abstractmethod
    def _open_card(self) -> bool:
        """Open a card connection; ``False`` if the field is empty."""

    @abc.abstractmethod
    def _close_card(self) -> None:
        """Close the card connection."""

    @abc.abstractmethod
    def _transmit_raw(self, apdu: bytes) -> tuple[bytes, int, int]:
        """Send one APDU over the live card connection."""

    @abc.abstractmethod
    def _get_atr(self) -> bytes:
        """The ATR reported for the live card connection."""


def _check_block(block: int) -> None:
    if not 0 <= block <= 0xFF:
        raise ValueError(f"block address out of range for a 1-byte P2: {block}")


def _check_length(length: int) -> None:
    if not 1 <= length <= 0xFF:
        raise ValueError(f"transfer length out of range: {length}")


def _check_slot(slot: int) -> None:
    if not 0 <= slot <= 0xFF:
        raise ValueError(f"key slot out of range: {slot}")
