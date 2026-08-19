"""Manual hardware check. Never run in CI -- it needs a reader and a tag.

Read-only by default: it identifies whatever tag is on the reader and dumps the
first bytes of user memory.

    uv run python examples/roundtrip.py

Pass --write to do the full round trip. That **overwrites user memory**, so it backs
the tag up first, writes a pattern, re-reads it after a removal and re-presentation,
and puts the original bytes back:

    uv run python examples/roundtrip.py --write

The removal step is the point of the exercise: it proves the data survives the RF
session ending, rather than being read back out of a cache.
"""

from __future__ import annotations

import argparse
import sys

import simple_nfc_tag as snt

PATTERN = b"simple-nfc-tag round trip 0123456789"


def describe(tag: snt.Card) -> None:
    print(f"  product   : {tag.product}")
    print(f"  uid       : {tag.uid.hex().upper()}")
    print(f"  user size : {tag.user_size} bytes ({tag.block_size}-byte blocks)")


def dump(tag: snt.Card, length: int = 32) -> None:
    length = min(length, tag.user_size)
    data = tag.read_bytes(0, length)
    print(f"  first {length:3d} : {data.hex(' ').upper()}")
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    print(f"  as text   : {printable}")


def round_trip(reader: snt.Reader, tag: snt.Card) -> int:
    size = min(len(PATTERN), tag.user_size)
    print(f"\nBacking up the first {size} bytes...")
    original = tag.read_bytes(0, size)
    print(f"  saved     : {original.hex(' ').upper()}")

    print("\nWriting the test pattern...")
    tag.write_bytes(0, PATTERN[:size])

    print("\nTake the tag off the reader, then put it back.")
    input("  press Enter once you have... ")

    tag = _reacquire(reader)
    if tag is None:
        print("  no tag came back; the original bytes are NOT restored yet", file=sys.stderr)
        return 1

    read_back = tag.read_bytes(0, size)
    ok = read_back == PATTERN[:size]
    print(f"  read back : {read_back!r}")
    print(f"  match     : {'yes' if ok else 'NO'}")

    print("\nRestoring the original bytes...")
    tag.write_bytes(0, original)
    restored = tag.read_bytes(0, size)
    restored_ok = restored == original
    print(f"  restored  : {restored.hex(' ').upper()}")
    print(f"  match     : {'yes' if restored_ok else 'NO'}")

    return 0 if (ok and restored_ok) else 1


def _reacquire(reader: snt.Reader) -> snt.Card | None:
    tag = reader.wait_for_tag(timeout=15)
    if tag is None:
        return None
    print(f"  tag back  : {tag.product} {tag.uid.hex().upper()}")
    return tag


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="overwrite user memory with a test pattern, then restore it",
    )
    parser.add_argument("--reader", help="substring of the PC/SC reader name")
    args = parser.parse_args()

    print("Attached readers:")
    for name in snt.list_readers():
        print(f"  {name}")

    with snt.connect(args.reader) as reader:
        print(f"\nUsing {reader.name} via {type(reader).__name__}")
        print("Present a tag...")
        tag = reader.wait_for_tag(timeout=15)
        if tag is None:
            print("No tag presented.", file=sys.stderr)
            return 1

        describe(tag)
        dump(tag)

        if not args.write:
            print("\nRead-only run. Pass --write for the full round trip.")
            return 0

        return round_trip(reader, tag)


if __name__ == "__main__":
    raise SystemExit(main())
