"""Manual hardware check for MIFARE Classic key and access-bit management.

Needs a reader and a Classic tag. Never run in CI.

Read-only by default: walks every sector, reports which well-known key opens it, and
decodes the trailer's access bits.

    uv run python examples/classic_keys.py

``--probe-keys`` tries every candidate as both A and B instead of stopping at the first
that works, which is what it takes to see a sector's whole key pair. Still read-only:

    uv run python examples/classic_keys.py --probe-keys

``--recover N`` brings sector N back to the transport configuration (open data,
key A = key B = FF FF FF FF FF FF). **This writes the sector trailer**, the one
irreversible operation on a Classic:

    uv run python examples/classic_keys.py --recover 1

It only helps a sector whose trailer can still be rewritten with a key the default
policy knows. A frozen trailer, or an unknown key, means the write is refused and
nothing changes. Use a sacrificial tag.
"""

from __future__ import annotations

import argparse
import sys

import simple_nfc_tag as snt
from simple_nfc_tag import access_bits
from simple_nfc_tag.cards.mifare_classic import MifareClassic
from simple_nfc_tag.keys import WELL_KNOWN_KEYS, KeyType


def _authenticates(reader: snt.Reader, block: int, key_type: KeyType, key: bytes) -> bool:
    """Whether one key opens one sector, leaving the session usable either way."""
    reader.load_key(0, key)
    try:
        reader.authenticate(block, key_type, 0)
    except snt.ApduError:
        reader.reset_card_connection()
        return False
    return True


def _opening_key(reader: snt.Reader, card: MifareClassic, sector: int) -> tuple[str, bytes] | None:
    """The first well-known key that authenticates a sector, tried A then B."""
    first_block = card._sector_bounds(sector)[0]
    for key in WELL_KNOWN_KEYS:
        for key_type in (KeyType.A, KeyType.B):
            if _authenticates(reader, first_block, key_type, key):
                return key_type.name, key
    return None


def _key_pair(reader: snt.Reader, card: MifareClassic, sector: int) -> dict[str, list[bytes]]:
    """Every well-known key that opens a sector, split into key A and key B.

    :func:`_opening_key` stops at its first hit, which hides the other half of the
    pair. Key A is write-only under every access condition and always reads back as
    zeros, so trying each candidate is the only way to learn it.
    """
    first_block = card._sector_bounds(sector)[0]
    found: dict[str, list[bytes]] = {"A": [], "B": []}
    for key in WELL_KNOWN_KEYS:
        for key_type in (KeyType.A, KeyType.B):
            if _authenticates(reader, first_block, key_type, key):
                found[key_type.name].append(key)
    return found


def survey(reader: snt.Reader, card: MifareClassic, *, probe_keys: bool = False) -> None:
    print(f"\n{card.product}  uid={card.uid.hex().upper()}  {card.sector_count} sectors\n")
    policy = card.keys
    for sector in range(card.sector_count):
        if probe_keys:
            pair = _key_pair(reader, card, sector)
            if not pair["A"] and not pair["B"]:
                print(f"  sector {sector:2d}  ** no well-known key opens it **")
                continue
            shown = "  ".join(
                f"key {letter}:" + ",".join(key.hex().upper() for key in keys)
                for letter, keys in pair.items()
                if keys
            )
            line = f"  sector {sector:2d}  {shown}"
            # Whichever key opened it will do to read the trailer back.
            card.keys = snt.StaticKeyProvider(
                key=(pair["A"] or pair["B"])[0],
                key_type=KeyType.A if pair["A"] else KeyType.B,
            )
        else:
            opened = _opening_key(reader, card, sector)
            if opened is None:
                print(f"  sector {sector:2d}  ** no well-known key opens it **")
                continue
            key_name, key = opened
            line = f"  sector {sector:2d}  key {key_name}:{key.hex().upper()}"
        try:
            trailer = card.read_sector_trailer(sector)
        except snt.ApduError:
            print(line + "  (authenticates, but the trailer will not read: locked)")
        except ValueError as exc:
            print(line + f"  (trailer is corrupt: {exc})")
        else:
            dead = access_bits.first_dead_data_block(trailer.access)
            note = f"  access={[''.join(map(str, c)) for c in trailer.access]}"
            if dead is not None:
                note += f"  ** data block {dead} is dead **"
            print(line + note)
        reader.reset_card_connection()
    card.keys = policy


def recover(card: MifareClassic, sector: int) -> int:
    print(f"\nAttempting to recover sector {sector} to the transport configuration...")
    print("  before:")
    _report_sector(card, sector)

    try:
        card.set_sector_keys(
            sector,
            snt.FACTORY_KEY,
            snt.FACTORY_KEY,
            i_understand_this_can_brick_the_sector=True,
        )
    except snt.ApduError as exc:
        print(f"\n  the trailer write was refused ({exc}).")
        print("  the sector's trailer cannot be rewritten with a key the policy knows;")
        print("  nothing was changed. this is the expected outcome for a frozen trailer.")
        return 1
    except snt.WriteVerificationError as exc:
        print(f"\n  the write did not land: {exc}")
        return 1

    print("\n  recovered. after:")
    card.keys = snt.StaticKeyProvider(key=snt.FACTORY_KEY)
    _report_sector(card, sector)
    return 0


def _report_sector(card: MifareClassic, sector: int) -> None:
    try:
        trailer = card.read_sector_trailer(sector)
    except (snt.ApduError, ValueError) as exc:
        print(f"    trailer will not read: {exc}")
        return
    print(f"    access = {[''.join(map(str, c)) for c in trailer.access]}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recover", type=int, metavar="SECTOR", help="rewrite a sector's trailer")
    parser.add_argument(
        "--probe-keys",
        action="store_true",
        help="try every well-known key as both A and B, reporting the whole pair",
    )
    args = parser.parse_args(argv)

    with snt.connect() as reader:
        card = reader.wait_for_tag(timeout=10)
        if card is None:
            print("no tag on the reader", file=sys.stderr)
            return 1
        if not isinstance(card, MifareClassic):
            print(f"not a MIFARE Classic: {card.product}", file=sys.stderr)
            return 1

        survey(reader, card, probe_keys=args.probe_keys)
        if args.recover is not None:
            return recover(card, args.recover)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
