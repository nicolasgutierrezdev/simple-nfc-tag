"""Test doubles shared across the suite.

These exercise the abstractions themselves -- the APDUs a reader builds, the status
words it rejects, the block arithmetic a card does. They are deliberately thin: the
in-memory tag images that behave like real silicon live in ``FakeReader``, in the
package proper, because that is a feature users get too.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator, Sequence

from simple_nfc_tag.cards import register_driver
from simple_nfc_tag.cards.base import Card
from simple_nfc_tag.readers.acr122u import ACR122U
from simple_nfc_tag.readers.base import Reader

#: What a stub can be told to answer with: a full APDU response, or an exception.
Response = tuple[bytes, int, int] | BaseException

SUCCESS: tuple[bytes, int, int] = (b"", 0x90, 0x00)

#: A real PC/SC contactless ATR, card name 0003 (Ultralight), captured from an
#: ACR122U with an NTAG213 on it.
ULTRALIGHT_ATR = bytes.fromhex("3B8F8001804F0CA0000003060300030000000068")
#: A well-formed ATR reporting a card name nothing has a driver for.
UNKNOWN_ATR = bytes.fromhex("3B8F8001804F0CA00000030603ABCD0000000024")
#: The same, with card name 0001 (MIFARE Classic 1K).
CLASSIC_1K_ATR = bytes.fromhex("3B8F8001804F0CA000000306030001000000006A")


class StubTransport:
    """The six :class:`Reader` hooks, backed by a script instead of hardware.

    Mixed in *before* a reader class so its hooks win, which is what lets the same
    transport sit under the base ``Reader`` and under the ACR122U driver.
    """

    def __init__(
        self,
        responses: list[Response] | None = None,
        *,
        present: bool = True,
        atr: bytes = ULTRALIGHT_ATR,
        default: Response = SUCCESS,
        name: str = "stub reader",
    ) -> None:
        super().__init__(name)  # type: ignore[call-arg]
        self.responses: list[Response] = list(responses or [])
        self.default = default
        self.present = present
        self.atr = atr

        #: Every APDU handed to the transport, in order.
        self.sent: list[bytes] = []
        self.acquire_count = 0
        self.release_count = 0
        self.open_count = 0
        self.close_count = 0

    def _acquire_reader(self) -> None:
        self.acquire_count += 1

    def _release_reader(self) -> None:
        self.release_count += 1

    def _open_card(self) -> bool:
        if not self.present:
            return False
        self.open_count += 1
        return True

    def _close_card(self) -> None:
        self.close_count += 1

    def _transmit_raw(self, apdu: bytes) -> tuple[bytes, int, int]:
        self.sent.append(apdu)
        answer = self.responses.pop(0) if self.responses else self.default
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def _get_atr(self) -> bytes:
        return self.atr

    @property
    def last_sent(self) -> bytes:
        """The most recent APDU, for one-command assertions."""
        return self.sent[-1]

    def answer(self, *responses: Response) -> None:
        """Queue further scripted answers."""
        self.responses.extend(responses)


class StubReader(StubTransport, Reader):
    """A bare reader with a scripted transport."""


class StubACR122U(StubTransport, ACR122U):
    """The ACR122U driver with a scripted transport under it."""


def pn532_reply(data: bytes = b"", status: int = 0x00) -> tuple[bytes, int, int]:
    """Wrap ``data`` the way the PN532 answers an InCommunicateThru."""
    return (b"\xd5\x43" + bytes([status]) + data, 0x90, 0x00)


class MemoryCard(Card):
    """A card whose blocks are a dict, for exercising the linear tier.

    The default layout has a hole in it -- block 7 is missing, the way a Classic
    sector trailer is -- so any arithmetic that assumes user blocks are contiguous
    fails here rather than on someone's tag.
    """

    product = "MemoryCard"
    block_size = 4

    def __init__(
        self,
        reader: Reader | None = None,
        uid: bytes = b"\x04\x01\x02\x03",
        user_blocks: Sequence[int] = (4, 5, 6, 8),
    ) -> None:
        super().__init__(reader, uid)  # type: ignore[arg-type]
        self.blocks: dict[int, bytes] = {}
        self._blocks = tuple(user_blocks)
        self.reads: list[int] = []
        self.writes: list[int] = []

    def _user_blocks(self) -> Sequence[int]:
        return self._blocks

    def read_block(self, index: int) -> bytes:
        self.reads.append(index)
        return self.blocks.get(index, bytes(self.block_size))

    def write_block(self, index: int, data: bytes) -> None:
        if len(data) != self.block_size:
            raise AssertionError(f"block write must be {self.block_size} bytes, got {len(data)}")
        self.writes.append(index)
        self.blocks[index] = bytes(data)


@contextlib.contextmanager
def driver_registered(driver: type[Card]) -> Iterator[type[Card]]:
    """Register a card driver for the duration of a test, then take it back out."""
    from simple_nfc_tag import cards

    register_driver(driver)
    try:
        yield driver
    finally:
        cards._DRIVERS.remove(driver)


# Re-exported so tests can reach the ABC without a second import path.
__all__ = [
    "CLASSIC_1K_ATR",
    "SUCCESS",
    "ULTRALIGHT_ATR",
    "Card",
    "MemoryCard",
    "Response",
    "StubACR122U",
    "StubReader",
    "StubTransport",
    "driver_registered",
    "pn532_reply",
]
