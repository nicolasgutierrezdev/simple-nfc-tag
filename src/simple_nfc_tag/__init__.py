"""simple-nfc-tag: tag-agnostic NFC data storage over PC/SC.

Reads and writes your own data on MIFARE Classic, Ultralight and NTAG21x tags through
any PC/SC reader.

    >>> import simple_nfc_tag as snt                       # doctest: +SKIP
    >>> with snt.connect() as reader:                      # doctest: +SKIP
    ...     tag = reader.wait_for_tag(timeout=5)
    ...     tag.write(["ABC123", 42])
    ...     tag.read()
    ['ABC123', 42]
"""

from __future__ import annotations

from simple_nfc_tag.access_bits import (
    READ_ONLY_TRAILER,
    TRANSPORT_DATA,
    TRANSPORT_TRAILER,
    decode_access_bits,
    encode_access_bits,
)
from simple_nfc_tag.cards import Card, identify
from simple_nfc_tag.cards.mifare_classic import SectorTrailer
from simple_nfc_tag.codecs import (
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    Codec,
    codec_for,
    known_codecs,
    register_codec,
)
from simple_nfc_tag.exceptions import (
    ApduError,
    AuthenticationError,
    CardError,
    CardFull,
    CardRemoved,
    DecodeError,
    FormatError,
    NdefNotSupported,
    NfcError,
    NoCardPresent,
    NoReaderFound,
    ReaderError,
    ReaderNotSupported,
    UnknownFormat,
    UnsupportedCard,
    WriteVerificationError,
)
from simple_nfc_tag.keys import (
    FACTORY_KEY,
    WELL_KNOWN_KEYS,
    DefaultKeyProvider,
    KeyProvider,
    KeyType,
    StaticKeyProvider,
)
from simple_nfc_tag.monitor import Monitor
from simple_nfc_tag.readers import ACR122U, PCSCReader, Reader, list_readers, open_reader

__version__ = "0.1.0"


def connect(name: str | None = None) -> Reader:
    """Open a reader and return it, ready for tag access.

    The driver is chosen from the PC/SC reader name; anything unrecognised falls back
    to standard PC/SC.

    :param name: a substring of the PC/SC reader name. Omit to take the first reader
        attached.
    """
    return open_reader(name).connect()


__all__ = [
    "ACR122U",
    "FACTORY_KEY",
    "I8",
    "I16",
    "I32",
    "I64",
    "READ_ONLY_TRAILER",
    "TRANSPORT_DATA",
    "TRANSPORT_TRAILER",
    "U8",
    "U16",
    "U32",
    "U64",
    "WELL_KNOWN_KEYS",
    "ApduError",
    "AuthenticationError",
    "Card",
    "CardError",
    "CardFull",
    "CardRemoved",
    "Codec",
    "DecodeError",
    "DefaultKeyProvider",
    "FormatError",
    "KeyProvider",
    "KeyType",
    "Monitor",
    "NdefNotSupported",
    "NfcError",
    "NoCardPresent",
    "NoReaderFound",
    "PCSCReader",
    "Reader",
    "ReaderError",
    "ReaderNotSupported",
    "SectorTrailer",
    "StaticKeyProvider",
    "UnknownFormat",
    "UnsupportedCard",
    "WriteVerificationError",
    "__version__",
    "codec_for",
    "connect",
    "decode_access_bits",
    "encode_access_bits",
    "identify",
    "known_codecs",
    "list_readers",
    "open_reader",
    "register_codec",
]
