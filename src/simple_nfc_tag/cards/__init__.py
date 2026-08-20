"""Tag drivers and identification.

Identification runs once per card presence, not once per read: it reads the PC/SC ATR,
decodes the card name, and offers the tag to each registered driver in turn.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from simple_nfc_tag.cards.atr import AtrInfo, parse_atr
from simple_nfc_tag.cards.base import Card
from simple_nfc_tag.exceptions import UnsupportedCard

if TYPE_CHECKING:  # pragma: no cover - typing only
    from simple_nfc_tag.readers.base import Reader

__all__ = ["AtrInfo", "Card", "identify", "known_drivers", "parse_atr", "register_driver"]

_DRIVERS: list[type[Card]] = []


def register_driver(driver: type[Card]) -> type[Card]:
    """Register a :class:`Card` subclass to be offered tags during identification.

    Usable as a decorator. Later registrations are tried first, so a registered
    driver overrides a built-in one for the tags it claims.
    """
    if driver not in _DRIVERS:
        _DRIVERS.insert(0, driver)
    return driver


def known_drivers() -> list[type[Card]]:
    """The registered drivers, in the order identification will try them."""
    return list(_DRIVERS)


def identify(reader: Reader) -> Card:
    """Work out what tag is on the reader and return a driver for it.

    Raises :class:`UnsupportedCard` if no driver claims the tag, which is a different
    situation from an empty field.
    """
    atr = parse_atr(reader.get_atr())
    uid = reader.get_uid()

    for driver in _DRIVERS:
        card = driver.probe(reader, atr, uid)
        if card is not None:
            return card

    raise UnsupportedCard(
        f"no driver for this tag: {atr.product} "
        f"(ATR {atr.raw.hex(' ').upper()}, UID {uid.hex().upper()})"
    )


# Imported for their registration side effect, at the bottom so the registry exists
# by the time they run. This order is the order identification tries them.
from simple_nfc_tag.cards import mifare_classic, ultralight  # noqa: E402

__all__ += ["mifare_classic", "ultralight"]
