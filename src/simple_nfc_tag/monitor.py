"""Background tag monitoring: callbacks instead of a polling loop you write yourself.

The service shape. A :class:`Monitor` runs a thread that watches one reader and calls
you when a tag arrives or leaves::

    with Monitor(reader, on_tag=lambda tag: print(tag.read())) as monitor:
        ...

Two things it does that a hand-rolled ``while True`` usually gets wrong:

**Debounce.** A tag left sitting on the reader is seen on every tick. Reporting it
every time is almost never what the caller wants, so the same UID is only reported
again after ``debounce`` seconds. This is the behaviour the original scanner script
had, minus its habit of mutating state inside the getter that reported it.

**Idle cost.** Waiting is delegated to :meth:`Reader.wait_for_change`, which on a
PC/SC reader blocks in the driver until the presence actually changes -- no wakeups
while nothing is happening, and detection in milliseconds rather than up to a full
poll interval. Readers without that facility fall back to sleeping, and the monitor
works either way.

Callbacks run on the monitor's thread, so anything they touch needs to be safe to
touch from there, and a slow callback delays the next detection.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from types import TracebackType
from typing import TYPE_CHECKING

from simple_nfc_tag.exceptions import NfcError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from simple_nfc_tag.cards.base import Card
    from simple_nfc_tag.readers.base import Reader

__all__ = ["Monitor"]

#: How long to wait for a presence change before looking again anyway.
_DEFAULT_POLL = 0.25


class Monitor:
    """Watches a reader on a background thread and reports tags as they come and go.

    :param reader: an already-connected reader, or one the monitor will connect.
    :param on_tag: called with the :class:`Card` each time a tag is reported.
    :param on_removed: called with the UID (bytes) when a reported tag leaves.
    :param on_error: called with any :class:`NfcError` raised while polling. Without
        it, errors are swallowed and polling continues -- a tag pulled off mid-read
        must not kill the thread.
    :param debounce: seconds before the *same* UID is reported again. ``0`` reports
        every time it is seen.
    :param poll_interval: how long a single wait lasts. With a reader that supports
        presence notification this is only an upper bound on how long :meth:`stop`
        takes to be noticed.
    """

    def __init__(
        self,
        reader: Reader,
        on_tag: Callable[[Card], None] | None = None,
        on_removed: Callable[[bytes], None] | None = None,
        on_error: Callable[[NfcError], None] | None = None,
        debounce: float = 2.0,
        poll_interval: float = _DEFAULT_POLL,
    ) -> None:
        if debounce < 0:
            raise ValueError(f"debounce cannot be negative: {debounce}")
        if poll_interval <= 0:
            raise ValueError(f"poll_interval must be positive: {poll_interval}")

        self.reader = reader
        self.on_tag = on_tag
        self.on_removed = on_removed
        self.on_error = on_error
        self.debounce = debounce
        self.poll_interval = poll_interval

        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        #: UID currently in the field, as far as the monitor knows.
        self._present: bytes | None = None
        #: When each UID was last reported, for the debounce.
        self._last_reported: dict[bytes, float] = {}

    def __repr__(self) -> str:
        state = "running" if self.is_running else "stopped"
        return f"<Monitor on {self.reader.name!r} {state}>"

    @property
    def is_running(self) -> bool:
        """Whether the monitor thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> Monitor:
        """Start watching. Idempotent."""
        if self.is_running:
            return self

        self.reader.connect()
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name=f"simple-nfc-tag monitor ({self.reader.name})",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self, timeout: float | None = 5.0) -> None:
        """Ask the thread to finish and wait for it. Safe to call when stopped."""
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)

    def __enter__(self) -> Monitor:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()

    def forget(self, uid: bytes | None = None) -> None:
        """Clear the debounce, for one UID or for all of them.

        Lets a caller say "report this tag again next time you see it" without waiting
        the window out -- after a failed read, say, where a retry is the whole point.
        """
        if uid is None:
            self._last_reported.clear()
        else:
            self._last_reported.pop(bytes(uid), None)

    # ------------------------------------------------------------------ internals

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except NfcError as error:
                # One bad read must not end the service. The tag being yanked
                # mid-exchange is a routine event, not a fatal one.
                self._present = None
                if self.on_error is not None:
                    self.on_error(error)

            if self._stop.is_set():
                break
            self.reader.wait_for_change(self.poll_interval)

    def _tick(self) -> None:
        tag = self.reader.current_tag()

        if tag is None:
            departed, self._present = self._present, None
            if departed is not None and self.on_removed is not None:
                self.on_removed(departed)
            return

        self._present = tag.uid
        if self._should_report(tag.uid):
            self._last_reported[tag.uid] = self._now()
            if self.on_tag is not None:
                self.on_tag(tag)

    def _should_report(self, uid: bytes) -> bool:
        last = self._last_reported.get(uid)
        if last is None:
            return True
        return (self._now() - last) >= self.debounce

    @staticmethod
    def _now() -> float:
        return time.monotonic()
