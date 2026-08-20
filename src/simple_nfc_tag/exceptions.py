"""Exception hierarchy.

Everything raised by this package derives from :class:`NfcError`. Three branches, one
per layer: :class:`ReaderError` for the PC/SC reader, :class:`CardError` for the tag,
:class:`FormatError` for the payload.
"""

from __future__ import annotations

__all__ = [
    "ApduError",
    "AuthenticationError",
    "CardError",
    "CardFull",
    "CardRemoved",
    "DecodeError",
    "FormatError",
    "NdefNotSupported",
    "NfcError",
    "NoCardPresent",
    "NoReaderFound",
    "ReaderError",
    "ReaderNotSupported",
    "UnknownFormat",
    "UnsupportedCard",
    "WriteVerificationError",
]


class NfcError(Exception):
    """Base class for every error raised by simple-nfc-tag."""


# --------------------------------------------------------------------------- reader


class ReaderError(NfcError):
    """A problem with the PC/SC reader itself, rather than with a tag."""


class NoReaderFound(ReaderError):
    """No PC/SC reader is connected, or none matched the requested name."""


class ReaderNotSupported(ReaderError):
    """The reader cannot do what was asked of it.

    Raised by :meth:`Reader.transceive` on readers with no ISO 14443-3 passthrough,
    and by peripherals a given model does not have.
    """


# --------------------------------------------------------------------------- card


class CardError(NfcError):
    """A problem with the tag currently on (or missing from) the reader."""


class NoCardPresent(CardError):
    """An operation needed a tag on the reader and the field was empty."""


class CardRemoved(CardError):
    """The tag left the field mid-exchange; the card connection is now dead."""


class UnsupportedCard(CardError):
    """The tag was identified but this package has no driver for it."""


class AuthenticationError(CardError):
    """No supplied key or password was accepted for this sector or page range."""


class CardFull(CardError):
    """The payload does not fit in the tag's user memory."""

    def __init__(self, needed: int, available: int) -> None:
        super().__init__(f"payload needs {needed} bytes, tag has {available} bytes of user memory")
        self.needed = needed
        self.available = available


class WriteVerificationError(CardError):
    """A write reported success, but the tag does not hold the bytes that were sent.

    Measured on an ACR122U with an NTAG213: a write to a page protected by ``AUTH0``
    answers ``90 00`` and leaves the page unchanged. :meth:`Card.write_bytes` reads
    back and compares unless ``verify=False``.
    """

    def __init__(self, offset: int, expected: bytes, actual: bytes) -> None:
        super().__init__(
            f"write of {len(expected)} bytes at offset {offset} did not land: "
            + _describe_difference(offset, expected, actual)
        )
        self.offset = offset
        #: What the caller asked to be written.
        self.expected = expected
        #: What reading the same range back actually returned.
        self.actual = actual


def _describe_difference(offset: int, expected: bytes, actual: bytes) -> str:
    """Name the first byte that differs."""
    if len(expected) != len(actual):
        return f"read back {len(actual)} bytes instead of {len(expected)}"
    for index, (want, got) in enumerate(zip(expected, actual, strict=True)):
        if want != got:
            return f"byte {offset + index} should be 0x{want:02X} but the tag holds 0x{got:02X}"
    return "the bytes match, which should not have raised"


# Status words worth naming: everything else is reported as raw hex.
_STATUS_WORDS = {
    (0x63, 0x00): "operation failed",
    (0x62, 0x82): "end of file reached before Le bytes",
    (0x67, 0x00): "wrong length",
    (0x68, 0x00): "class not supported",
    (0x69, 0x81): "command incompatible with file structure",
    (0x69, 0x82): "security status not satisfied (authentication required)",
    (0x69, 0x86): "command not allowed",
    (0x6A, 0x81): "function not supported",
    (0x6A, 0x82): "file or application not found",
    (0x6B, 0x00): "wrong parameters P1-P2 (address out of range)",
    (0x6D, 0x00): "instruction not supported",
    (0x6E, 0x00): "class not supported",
    (0x6F, 0x00): "no precise diagnosis",
}


class ApduError(CardError):
    """An APDU returned a status word other than ``90 00``.

    Carries both status bytes, a decoded meaning where one is known, and the command
    that produced them.
    """

    def __init__(self, sw1: int, sw2: int, apdu: bytes | None = None) -> None:
        self.sw1 = sw1
        self.sw2 = sw2
        self.apdu = bytes(apdu) if apdu is not None else None

        message = f"APDU failed with SW={sw1:02X}{sw2:02X}"
        meaning = _STATUS_WORDS.get((sw1, sw2))
        if meaning is None and sw1 == 0x6C:
            meaning = f"wrong Le, card expects {sw2}"
        if meaning is None and sw1 == 0x61:
            meaning = f"{sw2} response bytes available"
        if meaning is not None:
            message += f" ({meaning})"
        if self.apdu is not None:
            message += f" for command {self.apdu.hex(' ').upper()}"
        super().__init__(message)

    @property
    def status_word(self) -> int:
        """Both status bytes as one 16-bit int, for easy comparison."""
        return (self.sw1 << 8) | self.sw2


# --------------------------------------------------------------------------- format


class FormatError(NfcError):
    """The bytes on the tag are not a payload this package can work with."""


class DecodeError(FormatError):
    """A payload was structurally invalid: truncated, bad length, unknown type id."""


class UnknownFormat(FormatError):
    """The tag holds data in no format this package recognises."""


class NdefNotSupported(FormatError):
    """The tag holds an NDEF message, which this package does not decode."""

    def __init__(self) -> None:
        super().__init__(
            "tag contains an NDEF message (TLV 0x03); NDEF decoding is not supported. "
            "Use format='raw' to get the bytes verbatim."
        )
