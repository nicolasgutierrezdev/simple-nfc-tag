"""Reader drivers and the factory that picks one.

Everything reader-specific (APDU wrapping, vendor escape commands, PN532 passthrough)
lives in this subpackage and is not visible to ``cards`` or ``codecs``.

Driver selection matches a substring against the PC/SC reader name, the only thing
PC/SC reports before anything is opened. An ACR122U shows up as
``ACS ACR122U PICC Interface 0``; anything unrecognised falls back to
:class:`PCSCReader`, which speaks only standardised commands.
"""

from __future__ import annotations

from simple_nfc_tag.exceptions import NoReaderFound
from simple_nfc_tag.readers.acr122u import ACR122U
from simple_nfc_tag.readers.base import Reader
from simple_nfc_tag.readers.pcsc import PCSCReader, list_readers

__all__ = [
    "ACR122U",
    "PCSCReader",
    "Reader",
    "known_readers",
    "list_readers",
    "open_reader",
    "register_reader",
]

_DRIVERS: list[type[PCSCReader]] = []


def register_reader(driver: type[PCSCReader]) -> type[PCSCReader]:
    """Register a driver to be considered by :func:`open_reader`.

    The driver's ``match`` attribute is tested as a case-insensitive substring of the
    PC/SC reader name. Later registrations are tried first, so a more specific driver
    can override a built-in one.
    """
    if not getattr(driver, "match", ""):
        raise ValueError(f"{driver.__name__} needs a non-empty 'match' attribute to be registered")
    if driver not in _DRIVERS:
        _DRIVERS.insert(0, driver)
    return driver


def known_readers() -> list[type[PCSCReader]]:
    """The registered drivers, in the order :func:`open_reader` will try them."""
    return list(_DRIVERS)


def driver_for(name: str) -> type[PCSCReader]:
    """The driver class that claims a PC/SC reader name."""
    for driver in _DRIVERS:
        if driver.match.lower() in name.lower():
            return driver
    return PCSCReader


def open_reader(name: str | None = None) -> Reader:
    """Build a driver for an attached reader, without connecting to it yet.

    :param name: a substring of the PC/SC reader name. Omit to take the first reader
        attached.
    """
    available = list_readers()
    if not available:
        raise NoReaderFound("no PC/SC reader is attached")

    if name is None:
        chosen = available[0]
    else:
        matches = [candidate for candidate in available if name.lower() in candidate.lower()]
        if not matches:
            raise NoReaderFound(
                f"no PC/SC reader matching {name!r}; attached readers: {', '.join(available)}"
            )
        chosen = matches[0]

    return driver_for(chosen)(chosen)


register_reader(ACR122U)
