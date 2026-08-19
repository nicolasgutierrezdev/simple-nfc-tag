"""ACS ACR122U driver.

The ACR122U is a PN532 behind a PC/SC front end, which is what makes it worth a
driver of its own: the PN532 can be addressed directly through a vendor pseudo-APDU,
giving the raw ISO 14443-3 passthrough that :meth:`Reader.transceive` promises and
generic PC/SC cannot offer. That passthrough is the only way to tell an NTAG213 from
an NTAG216, and the only way to run ``PWD_AUTH``.

Everything here is vendor-specific by definition, which is exactly why it is confined
to this module.
"""

from __future__ import annotations

from typing import ClassVar

from simple_nfc_tag.exceptions import ApduError, ReaderError
from simple_nfc_tag.readers.pcsc import PCSCReader

__all__ = ["ACR122U"]

# Vendor pseudo-APDU that hands the payload straight to the PN532.
_DIRECT_TRANSMIT = b"\xff\x00\x00\x00"
# PN532 InCommunicateThru: send bytes to the selected target with no framing added.
_IN_COMMUNICATE_THRU = b"\xd4\x42"
_IN_COMMUNICATE_THRU_REPLY = b"\xd5\x43"

# PN532 error codes worth naming; the rest are reported by value.
_PN532_ERRORS = {
    0x01: "timeout waiting for the tag",
    0x02: "CRC error in the tag's answer",
    0x03: "parity error in the tag's answer",
    0x04: "bit-count error during anticollision",
    0x07: "buffer overflow",
    0x0A: "the tag left the field",
    0x13: "the tag did not understand the command",
    0x14: "authentication failed",
    0x25: "the PN532 is not in the right state for this command",
}


class ACR122U(PCSCReader):
    """An ACS ACR122U (and the ACR122-compatible readers that share its firmware)."""

    #: Substring the reader factory matches against the PC/SC reader name.
    match: ClassVar[str] = "ACR122"

    def transceive(self, payload: bytes) -> bytes:
        """Send a raw ISO 14443-3 command to the tag through the PN532.

        The payload goes out inside ``FF 00 00 00 <Lc> D4 42 …`` and the answer comes
        back as ``D5 43 <status> <data>``; a non-zero status is the PN532 reporting a
        radio-level failure, which is a different thing from a status word and has to
        be raised as one.
        """
        if not payload:
            raise ValueError("transceive needs at least one byte to send")

        frame = _IN_COMMUNICATE_THRU + bytes(payload)
        if len(frame) > 0xFF:
            raise ValueError(f"payload too long for a single PN532 frame: {len(payload)} bytes")

        data, sw1, sw2 = self.transmit_raw(_DIRECT_TRANSMIT + bytes([len(frame)]) + frame)

        # Some firmware answers 61 XX and holds the reply for a GET RESPONSE.
        if sw1 == 0x61:
            data, sw1, sw2 = self.transmit_raw(bytes([0xFF, 0xC0, 0x00, 0x00, sw2]))
        if (sw1, sw2) != (0x90, 0x00):
            raise ApduError(sw1, sw2, _DIRECT_TRANSMIT + bytes([len(frame)]) + frame)

        return _unwrap_pn532_reply(data)

    # ---------------------------------------------------------------- peripherals

    def set_buzzer(self, enabled: bool) -> None:
        """Turn the card-detection beep on or off.

        A reader-level setting that persists until changed, but it has to be sent over
        a *card* connection: doing it with an empty field needs ``SCardControl`` escape
        commands, which on Windows require a per-reader registry opt-in.
        """
        self.transmit(bytes([0xFF, 0x00, 0x52, 0xFF if enabled else 0x00, 0x00]))

    def set_led(self, red: bool = False, green: bool = False) -> None:
        """Set the two status LEDs, leaving blinking and the buzzer alone."""
        # Bits 0-1 are the final state, bits 2-3 mask which of the two we are setting.
        state = (0x01 if red else 0x00) | (0x02 if green else 0x00) | 0x0C
        self.transmit(bytes([0xFF, 0x00, 0x40, state, 0x04, 0x00, 0x00, 0x00, 0x00]))

    # ------------------------------------------------------------------- vendor

    def firmware_version(self) -> str:
        """The reader's firmware string, e.g. ``ACR122U207``.

        The reader answers with the tail of the string in the status-word position
        rather than a real status word, so this is the one command whose ``SW`` bytes
        are payload.
        """
        data, sw1, sw2 = self.transmit_raw(b"\xff\x00\x48\x00\x00")
        return (bytes(data) + bytes([sw1, sw2])).decode("ascii", errors="replace")


def _unwrap_pn532_reply(data: bytes) -> bytes:
    """Strip the ``D5 43 <status>`` header off a PN532 answer."""
    if len(data) < 3 or not data.startswith(_IN_COMMUNICATE_THRU_REPLY):
        raise ReaderError(
            f"unexpected answer from the PN532: {data.hex(' ').upper() if data else '<empty>'}"
        )

    status = data[2]
    if status != 0x00:
        meaning = _PN532_ERRORS.get(status, "unknown PN532 error")
        raise ReaderError(f"PN532 rejected the command: {meaning} (status 0x{status:02X})")

    return data[3:]
