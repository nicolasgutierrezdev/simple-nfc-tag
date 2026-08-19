"""Watch a reader and print tags as they come and go. Ctrl-C to stop.

    uv run python examples/monitor.py

Every line is timestamped from when the monitor started, so the gap between lifting a
tag and seeing REMOVED is the real detection latency.

``--poll`` is deliberately long by default. A PC/SC reader is asked to wake the thread
when the card presence actually changes, so nothing should ever have to wait for the
poll interval to expire -- if you lift the tag and see REMOVED a fraction of a second
later despite a 30-second poll interval, that is the driver notification working. Pass
``--poll 1`` to compare against something closer to a plain polling loop.
"""

from __future__ import annotations

import argparse
import time

import simple_nfc_tag as snt

START = time.monotonic()


def stamp() -> str:
    return f"{time.monotonic() - START:7.3f}s"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", help="substring of the PC/SC reader name")
    parser.add_argument(
        "--debounce",
        type=float,
        default=2.0,
        help="seconds before the same tag is reported again (default: 2)",
    )
    parser.add_argument(
        "--poll",
        type=float,
        default=30.0,
        help="longest wait between looks; a presence change cuts it short (default: 30)",
    )
    parser.add_argument("--read", action="store_true", help="also read each tag's payload")
    args = parser.parse_args()

    def on_tag(tag: snt.Card) -> None:
        line = f"{stamp()}  ARRIVED  {tag.product:18s} {tag.uid.hex().upper()}"
        if args.read:
            try:
                line += f"  -> {tag.read()!r}"
            except snt.NfcError as exc:
                line += f"  -> {type(exc).__name__}: {exc}"
        print(line, flush=True)

    def on_removed(uid: bytes) -> None:
        print(f"{stamp()}  REMOVED  {'':18s} {uid.hex().upper()}", flush=True)

    def on_error(exc: snt.NfcError) -> None:
        print(f"{stamp()}  ERROR    {type(exc).__name__}: {exc}", flush=True)

    with snt.connect(args.reader) as reader:
        print(f"watching {reader.name} via {type(reader).__name__}", flush=True)
        print(f"debounce {args.debounce}s, poll {args.poll}s -- Ctrl-C to stop\n", flush=True)

        with snt.Monitor(
            reader,
            on_tag=on_tag,
            on_removed=on_removed,
            on_error=on_error,
            debounce=args.debounce,
            poll_interval=args.poll,
        ):
            try:
                while True:
                    time.sleep(0.5)
            except KeyboardInterrupt:
                print("\nstopped", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
