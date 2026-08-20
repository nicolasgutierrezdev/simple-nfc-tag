"""MIFARE Ultralight and NTAG21x.

All of these report card name ``0003`` to PC/SC and differ only in memory size, so
identification is the job of this module. Two routes:

1. ``GET_VERSION`` (``0x60``) through :meth:`Reader.transceive`; byte 6 is the storage
   size. Exact, but needs a reader with a raw passthrough.
2. Otherwise, probing for the last readable page. A read past the end of memory
   answers ``63 00``; a read at the end succeeds and wraps around to page 0. Both
   captured from an ACR122U with an NTAG213.

Addressing quirk: a read returns 16 bytes (four pages) whatever was asked for, but a
write takes exactly one 4-byte page. Unaligned writes need a read-modify-write, which
the linear tier in :class:`~simple_nfc_tag.cards.base.Card` handles.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from simple_nfc_tag.cards import register_driver
from simple_nfc_tag.cards.base import Card
from simple_nfc_tag.exceptions import (
    AuthenticationError,
    CardError,
    NfcError,
    ReaderNotSupported,
)
from simple_nfc_tag.readers.base import Reader

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Sequence

    from simple_nfc_tag.cards.atr import AtrInfo

__all__ = ["NTAG213", "NTAG215", "NTAG216", "Ultralight"]

#: PC/SC card names that mean "something in the Ultralight family".
_ULTRALIGHT_CARD_NAMES = (0x0003, 0x003A)

#: GET_VERSION command code.
_GET_VERSION = b"\x60"

#: PWD_AUTH: the command byte, followed by the 4-byte password.
_PWD_AUTH = b"\x1b"

#: PROT, bit 7 of the ACCESS byte (the first byte of CFG1). Set, protection covers
#: reads as well as writes; clear, protected pages stay readable by anyone.
_PROT = 0x80

#: Pages 0-3 hold the UID, lock bytes and the capability container.
_FIRST_USER_PAGE = 4

#: Pages an Ultralight read returns in one go.
_PAGES_PER_READ = 4


@register_driver
class Ultralight(Card):
    """A MIFARE Ultralight: 16 pages, 48 bytes of user memory.

    Base class for the NTAG21x drivers, and the fallback for an unidentifiable tag in
    this family.
    """

    product: ClassVar[str] = "MIFARE Ultralight"
    block_size: ClassVar[int] = 4

    #: Total pages on the tag, including the reserved ones.
    total_pages: ClassVar[int] = 16
    #: Pages of user memory, starting at page 4.
    user_pages: ClassVar[int] = 12
    #: GET_VERSION storage byte that identifies this product, if it has one.
    storage_code: ClassVar[int | None] = None

    @classmethod
    def probe(cls, reader: Reader, atr: AtrInfo, uid: bytes) -> Card | None:
        # Only the registered class probes; the subclasses are products it returns,
        # not independent candidates.
        if cls is not Ultralight or atr.card_name not in _ULTRALIGHT_CARD_NAMES:
            return None

        driver = _by_version(reader) or _by_probing(reader)
        return driver(reader, uid)

    def authenticate(self, password: bytes, pack: bytes | None = None) -> bytes:
        """Prove a password with ``PWD_AUTH``, returning the tag's 2-byte PACK.

        Protection lasts one RF session and is forgotten when the tag leaves the field,
        so this is called once per card presence.

        :param password: the 4-byte password.
        :param pack: if given, the 2-byte acknowledgement expected back. Checking it
            stops a fake tag from harvesting passwords: only a tag that already knew
            the password can return the right PACK.

        Raises :class:`AuthenticationError` if the tag refuses the password or returns
        the wrong PACK, and :class:`ReaderNotSupported` on a reader with no raw
        passthrough, since ``PWD_AUTH`` has no PC/SC pseudo-APDU.
        """
        if len(password) != 4:
            raise ValueError(f"an NTAG password is 4 bytes, got {len(password)}")
        if pack is not None and len(pack) != 2:
            raise ValueError(f"a PACK is 2 bytes, got {len(pack)}")

        try:
            answer = self._reader.transceive(_PWD_AUTH + bytes(password))
        except ReaderNotSupported:
            raise
        except NfcError as exc:
            # A refused password deselects the tag; without this every later read
            # fails for a reason that looks nothing like a bad password.
            self._reader.reset_card_connection()
            raise AuthenticationError(f"this {self.product} refused the password") from exc

        if len(answer) < 2:
            raise AuthenticationError(
                f"expected a 2-byte PACK from this {self.product}, got "
                f"{answer.hex(' ').upper() or '<nothing>'}"
            )

        returned = answer[:2]
        if pack is not None and returned != pack:
            raise AuthenticationError(
                f"the tag answered with PACK {returned.hex().upper()}, not the expected "
                f"{bytes(pack).hex().upper()}; it does not hold the password you think it does"
            )
        return returned

    def set_password(
        self,
        password: bytes,
        pack: bytes,
        protect_from: int | None = None,
        protect_reads: bool | None = None,
    ) -> None:
        """Set the tag's password, and optionally what its protection covers.

        :param password: the new 4-byte password.
        :param pack: the new 2-byte acknowledgement the tag will return.
        :param protect_from: page number to protect from, ``0xFF`` to disable
            protection, or ``None`` (the default) to leave the setting alone.
        :param protect_reads: ``True`` to protect reads as well as writes, ``False``
            for writes only, or ``None`` (the default) to leave the setting alone.

        **The password is not readable afterwards.** A tag answers reads of its
        password page with zeros whatever it holds. Write it down before calling this.

        Protection is changed only after the new password has been proved on a fresh
        session: the tag is re-selected, ``PWD_AUTH`` is run, and the PACK is checked.
        Otherwise a typo in ``password`` would protect pages with a secret nobody
        knows, which is unrecoverable on a tag with a non-zero ``AUTHLIM``.

        The two settings are independent and both are needed for privacy. ``AUTH0``
        (``protect_from``) says where protection starts; ``PROT`` (``protect_reads``)
        says what it covers. On a factory tag ``PROT`` is clear, so protection covers
        writes only and protected pages stay readable by anyone. ``AUTH0`` is written
        last, so protection is never half-applied.

        ``AUTHLIM`` and ``CFGLCK`` are deliberately not exposed: both can brick a tag
        permanently.
        """
        if len(password) != 4:
            raise ValueError(f"an NTAG password is 4 bytes, got {len(password)}")
        if len(pack) != 2:
            raise ValueError(f"a PACK is 2 bytes, got {len(pack)}")
        if protect_from is not None and not 0 <= protect_from <= 0xFF:
            raise ValueError(f"protect_from must be a page number or 0xFF: {protect_from}")

        config = self._config_page()
        self._reader.update_binary(config + 2, bytes(password))
        self._reader.update_binary(config + 3, bytes(pack) + b"\x00\x00")

        if protect_from is None and protect_reads is None:
            return

        # Prove the password on a session that has not already been authenticated, so
        # a tag still holding the old one cannot pass this check. Guards PROT as much
        # as AUTH0: setting PROT while AUTH0 is in force would close reads behind a
        # password the caller may not have set.
        self._reader.reset_card_connection()
        self.authenticate(password, pack=pack)

        if protect_reads is not None:
            cfg1 = self._reader.read_binary(config + 1, self.block_size)
            access = cfg1[0] | _PROT if protect_reads else cfg1[0] & ~_PROT
            self._reader.update_binary(config + 1, bytes([access]) + cfg1[1:])

        if protect_from is not None:
            cfg0 = self._reader.read_binary(config, self.block_size)
            self._reader.update_binary(config, cfg0[:3] + bytes([protect_from]))

    def _config_page(self) -> int:
        """Address of CFG0. The four configuration pages are the last four."""
        if self.storage_code is None:
            raise CardError(
                f"a {self.product} has no configuration pages; passwords are an NTAG21x feature"
            )
        return self.total_pages - 4

    def _user_blocks(self) -> Sequence[int]:
        return range(_FIRST_USER_PAGE, _FIRST_USER_PAGE + self.user_pages)

    def read_block(self, index: int) -> bytes:
        return self._reader.read_binary(index, self.block_size)

    def write_block(self, index: int, data: bytes) -> None:
        if len(data) != self.block_size:
            raise ValueError(f"an Ultralight page is {self.block_size} bytes, got {len(data)}")
        self._reader.update_binary(index, data)

    def _read_run(self, blocks: Sequence[int]) -> bytes:
        """Fetch up to four pages per APDU.

        User pages are contiguous on this family, so a run costs one exchange per
        16 bytes rather than four.
        """
        data = bytearray()
        position = 0
        while position < len(blocks):
            span = min(_PAGES_PER_READ, len(blocks) - position)
            data += self._reader.read_binary(blocks[position], span * self.block_size)
            position += span
        return bytes(data)


class NTAG213(Ultralight):
    """NTAG213: 144 bytes of user memory."""

    product: ClassVar[str] = "NTAG213"
    total_pages: ClassVar[int] = 45
    user_pages: ClassVar[int] = 36
    storage_code: ClassVar[int | None] = 0x0F


class NTAG215(Ultralight):
    """NTAG215: 504 bytes of user memory."""

    product: ClassVar[str] = "NTAG215"
    total_pages: ClassVar[int] = 135
    user_pages: ClassVar[int] = 126
    storage_code: ClassVar[int | None] = 0x11


class NTAG216(Ultralight):
    """NTAG216: 888 bytes of user memory."""

    product: ClassVar[str] = "NTAG216"
    total_pages: ClassVar[int] = 231
    user_pages: ClassVar[int] = 222
    storage_code: ClassVar[int | None] = 0x13


#: Smallest first, so probing stops at the tag's actual size.
_FAMILY: tuple[type[Ultralight], ...] = (Ultralight, NTAG213, NTAG215, NTAG216)


def _by_version(reader: Reader) -> type[Ultralight] | None:
    """Identify from GET_VERSION, or ``None`` if the tag or reader cannot do it.

    A plain Ultralight has no GET_VERSION, and a reader with no passthrough cannot
    ask. Neither is a failure; the answer comes from probing instead.
    """
    try:
        version = reader.transceive(_GET_VERSION)
    except ReaderNotSupported:
        return None
    except NfcError:
        # The tag refused the command, which deselects it: rebuild the session.
        reader.reset_card_connection()
        return None

    if len(version) < 7:
        return None

    storage = version[6]
    for driver in _FAMILY:
        if driver.storage_code == storage:
            return driver
    return None


def _by_probing(reader: Reader) -> type[Ultralight]:
    """Identify by finding where memory stops.

    Reading the last page succeeds; reading one page further does not. Candidates are
    tried smallest first and the walk stops at the first refusal, costing one failed
    read whatever the size; each failure costs an RF session rebuild.

    An unrecognisable tag falls back to plain Ultralight, the smallest layout in the
    family, so the fallback can only under-use memory, never write past its end.
    """
    identified: type[Ultralight] = Ultralight
    for driver in _FAMILY[1:]:
        if not _page_readable(reader, driver.total_pages - 1):
            break
        identified = driver
    return identified


def _page_readable(reader: Reader, page: int) -> bool:
    """Whether a page can be read, without treating a refusal as an error.

    A refusal deselects the tag, so the session is rebuilt before returning; otherwise
    the first probe past the end of memory breaks every read that follows.
    """
    if page > 0xFF:
        return False
    try:
        _, sw1, sw2 = reader.transmit_raw(bytes([0xFF, 0xB0, 0x00, page, 0x04]))
    except CardError:
        reader.reset_card_connection()
        return False
    if (sw1, sw2) == (0x90, 0x00):
        return True
    reader.reset_card_connection()
    return False
