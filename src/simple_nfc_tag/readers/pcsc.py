"""Generic PC/SC reader driver, built on pyscard.

This is the baseline every other driver specialises. It speaks only standardised
PC/SC part-3 pseudo-APDUs, so it works with any contactless reader that exposes
them -- and it deliberately does *not* implement :meth:`~Reader.transceive`, which
has no standard form.

pyscard is imported lazily. The package is a hard dependency, but keeping the import
out of module scope means an environment with a broken or missing PC/SC stack still
imports ``simple_nfc_tag``, so the hardware-free test path never depends on it.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, ClassVar

from simple_nfc_tag.exceptions import (
    CardRemoved,
    NfcError,
    NoCardPresent,
    NoReaderFound,
    ReaderError,
)
from simple_nfc_tag.readers.base import Reader

if TYPE_CHECKING:  # pragma: no cover - typing only
    from smartcard.CardConnection import CardConnection

__all__ = ["PCSCReader", "list_readers"]

# PC/SC result codes worth reacting to by value rather than by message text.
_SCARD_W_REMOVED_CARD = 0x80100069
_SCARD_W_RESET_CARD = 0x80100068
_SCARD_E_NO_SMARTCARD = 0x8010000C


def _import_pyscard() -> Any:
    """Import pyscard, or explain what to install."""
    try:
        import smartcard.System
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ReaderError(
            "pyscard is required to talk to a PC/SC reader. Install it with "
            "'pip install pyscard', and on Linux make sure pcscd and libpcsclite "
            "are present."
        ) from exc
    return smartcard


def list_readers() -> list[str]:
    """Names of every PC/SC reader currently attached."""
    smartcard = _import_pyscard()
    try:
        return [str(reader) for reader in smartcard.System.readers()]
    # pyscard raises undocumented exception types out of the PC/SC context; all of
    # them mean the same thing to a caller, and none should escape as a raw pyscard
    # class.
    except Exception as exc:
        raise ReaderError(f"could not query the PC/SC subsystem: {exc}") from exc


class PCSCReader(Reader):
    """A contactless reader addressed through PC/SC.

    :param name: PC/SC reader name, or a substring of one. Omit to take the first
        reader attached.
    """

    #: Substring the factory matches against the PC/SC reader name. Empty on this
    #: class: it is the fallback every reader gets, not one that claims a model.
    match: ClassVar[str] = ""

    def __init__(self, name: str | None = None) -> None:
        super().__init__(name or "")
        self._requested = name
        self._reader: Any = None
        self._connection: CardConnection | None = None
        #: Long-lived context and last known reader state, used for presence waiting.
        self._status_ctx: Any = None
        self._status_state: int = 0

    # ---------------------------------------------------------------- lifecycle

    def _acquire_reader(self) -> None:
        smartcard = _import_pyscard()
        try:
            available = smartcard.System.readers()
        except Exception as exc:  # see list_readers
            raise ReaderError(f"could not query the PC/SC subsystem: {exc}") from exc

        if not available:
            raise NoReaderFound("no PC/SC reader is attached")

        if self._requested is None:
            self._reader = available[0]
        else:
            matches = [r for r in available if self._requested.lower() in str(r).lower()]
            if not matches:
                names = ", ".join(str(r) for r in available)
                raise NoReaderFound(
                    f"no PC/SC reader matching {self._requested!r}; attached readers: {names}"
                )
            self._reader = matches[0]

        self._name = str(self._reader)

    def _release_reader(self) -> None:
        self._release_status_context()
        self._reader = None

    def _open_card(self) -> bool:
        smartcard = _import_pyscard()
        connection = self._reader.createConnection()
        try:
            connection.connect()
        except smartcard.Exceptions.NoCardException:
            return False
        except smartcard.Exceptions.CardConnectionException as exc:
            if _hresult(exc) in (_SCARD_E_NO_SMARTCARD, _SCARD_W_REMOVED_CARD):
                return False
            raise _translate(exc) from exc
        self._connection = connection
        return True

    def _close_card(self) -> None:
        connection, self._connection = self._connection, None
        if connection is None:
            return
        # Best effort: the usual reason for a disconnect to fail is that the tag is
        # already gone, which is exactly the state being cleaned up.
        with contextlib.suppress(Exception):
            connection.disconnect()

    # --------------------------------------------------------------------- APDU

    def _transmit_raw(self, apdu: bytes) -> tuple[bytes, int, int]:
        if self._connection is None:
            raise NoCardPresent("no card connection is open")
        smartcard = _import_pyscard()
        try:
            data, sw1, sw2 = self._connection.transmit(list(apdu))
        except smartcard.Exceptions.CardConnectionException as exc:
            raise _translate(exc) from exc
        return bytes(data), sw1, sw2

    def _get_atr(self) -> bytes:
        if self._connection is None:
            raise NoCardPresent("no card connection is open")
        return bytes(self._connection.getATR())

    # ------------------------------------------------------------ presence waiting

    def wait_for_change(self, timeout: float | None = None) -> bool:
        """Block in the PC/SC driver until this reader's card presence changes.

        ``SCardGetStatusChange`` parks the thread in the driver, so a monitor sitting
        over an empty reader costs nothing at all and notices a tap in milliseconds,
        rather than waking on a timer and finding nothing every time.

        Falls back to the base class's sleep if the PC/SC subsystem will not play
        along -- a missing context, a driver without notification support -- because a
        monitor that polls slowly is far better than one that does not run.
        """
        try:
            return self._wait_via_pcsc(timeout)
        # Any failure here is survivable: the base class's sleep is always correct,
        # just costlier.
        except Exception:
            self._release_status_context()
            return super().wait_for_change(timeout)

    def _wait_via_pcsc(self, timeout: float | None) -> bool:
        smartcard = _import_pyscard()
        scard = smartcard.scard

        context = self._status_context()
        milliseconds = scard.INFINITE if timeout is None else max(1, int(timeout * 1000))
        current = self._status_state

        result, states = scard.SCardGetStatusChange(context, milliseconds, [(self._name, current)])
        if result == scard.SCARD_E_TIMEOUT:
            return False
        if result != scard.SCARD_S_SUCCESS:
            raise ReaderError(f"SCardGetStatusChange failed: {result}")

        _, event_state, _atr = states[0]
        # The driver ORs in a "changed" bit; strip it before storing, or the next call
        # is comparing against a state the driver never reports.
        self._status_state = event_state & ~scard.SCARD_STATE_CHANGED
        return bool(event_state & scard.SCARD_STATE_CHANGED)

    def _status_context(self) -> Any:
        if self._status_ctx is None:
            smartcard = _import_pyscard()
            scard = smartcard.scard
            result, context = scard.SCardEstablishContext(scard.SCARD_SCOPE_USER)
            if result != scard.SCARD_S_SUCCESS:
                raise ReaderError(f"could not establish a PC/SC context: {result}")
            self._status_ctx = context
            self._status_state = scard.SCARD_STATE_UNAWARE
        return self._status_ctx

    def _release_status_context(self) -> None:
        context, self._status_ctx = self._status_ctx, None
        if context is None:
            return
        smartcard = _import_pyscard()
        with contextlib.suppress(Exception):
            smartcard.scard.SCardReleaseContext(context)


def _hresult(exc: BaseException) -> int | None:
    """The PC/SC result code behind a pyscard exception, if it carries one."""
    value = getattr(exc, "hresult", None)
    if value is None:
        return None
    # pyscard reports these as signed 32-bit values on some platforms.
    return int(value) & 0xFFFFFFFF


def _translate(exc: BaseException) -> NfcError:
    """Map a pyscard exception onto this package's hierarchy."""
    code = _hresult(exc)
    if code in (_SCARD_W_REMOVED_CARD, _SCARD_W_RESET_CARD):
        return CardRemoved("the tag left the field during the exchange")
    if code == _SCARD_E_NO_SMARTCARD:
        return NoCardPresent("no tag on the reader")
    if code is None:
        # Older pyscard builds only report the condition in the message text.
        text = str(exc).lower()
        if "removed" in text or "reset" in text:
            return CardRemoved("the tag left the field during the exchange")
        if "no smart card" in text or "no card" in text:
            return NoCardPresent("no tag on the reader")
    return ReaderError(f"PC/SC transport error: {exc}")
