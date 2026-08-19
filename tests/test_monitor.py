"""The background monitor: arrival, departure, debounce, and clean shutdown.

Threads make for flaky tests if you sleep and hope, so these drive the fake reader's
presence directly and wait on events with a timeout rather than on the clock.
"""

from __future__ import annotations

import threading

import pytest

from simple_nfc_tag.exceptions import CardRemoved, NfcError
from simple_nfc_tag.monitor import Monitor
from simple_nfc_tag.readers.fake import FakeNTAG213, FakeReader

UID_A = bytes.fromhex("049AEEE2307380")
UID_B = bytes.fromhex("04112233445566")

# Long enough that a slow machine does not fail the test, short enough to stay quick.
TIMEOUT = 5.0


class Recorder:
    """Collects callbacks and lets a test block until the next one arrives."""

    def __init__(self) -> None:
        self.tags: list[bytes] = []
        self.removed: list[bytes] = []
        self.errors: list[NfcError] = []
        self._event = threading.Event()

    def on_tag(self, tag) -> None:
        self.tags.append(tag.uid)
        self._event.set()

    def on_removed(self, uid: bytes) -> None:
        self.removed.append(uid)
        self._event.set()

    def on_error(self, error: NfcError) -> None:
        self.errors.append(error)
        self._event.set()

    def wait(self, count: int = 1) -> bool:
        """Wait until at least ``count`` callbacks have landed in total."""
        while len(self.tags) + len(self.removed) + len(self.errors) < count:
            self._event.clear()
            if not self._event.wait(TIMEOUT):
                return False
        return True


@pytest.fixture
def reader():
    return FakeReader(FakeNTAG213(uid=UID_A))


@pytest.fixture
def recorder():
    return Recorder()


def monitor_for(reader, recorder, **kwargs):
    kwargs.setdefault("poll_interval", 0.01)
    kwargs.setdefault("debounce", 0)
    return Monitor(
        reader,
        on_tag=recorder.on_tag,
        on_removed=recorder.on_removed,
        on_error=recorder.on_error,
        **kwargs,
    )


class TestLifecycle:
    def test_starts_and_stops(self, reader, recorder):
        monitor = monitor_for(reader, recorder)
        assert not monitor.is_running
        monitor.start()
        assert monitor.is_running
        monitor.stop()
        assert not monitor.is_running

    def test_start_is_idempotent(self, reader, recorder):
        monitor = monitor_for(reader, recorder)
        with monitor:
            thread = monitor._thread
            monitor.start()
            assert monitor._thread is thread

    def test_stop_without_start_is_harmless(self, reader, recorder):
        monitor_for(reader, recorder).stop()

    def test_context_manager_stops_on_the_way_out(self, reader, recorder):
        with monitor_for(reader, recorder) as monitor:
            assert monitor.is_running
        assert not monitor.is_running

    def test_the_reader_is_connected_for_you(self, reader, recorder):
        assert not reader.is_connected
        with monitor_for(reader, recorder):
            assert reader.is_connected

    def test_repr_says_whether_it_is_running(self, reader, recorder):
        monitor = monitor_for(reader, recorder)
        assert "stopped" in repr(monitor)
        with monitor:
            assert "running" in repr(monitor)

    @pytest.mark.parametrize(
        ("kwargs", "match"),
        [({"debounce": -1}, "debounce"), ({"poll_interval": 0}, "poll_interval")],
    )
    def test_nonsense_arguments_are_refused(self, reader, recorder, kwargs, match):
        with pytest.raises(ValueError, match=match):
            monitor_for(reader, recorder, **kwargs)


class TestEvents:
    def test_a_tag_already_present_is_reported(self, reader, recorder):
        with monitor_for(reader, recorder):
            assert recorder.wait()
        assert recorder.tags == [UID_A]

    def test_a_tag_arriving_later_is_reported(self, recorder):
        reader = FakeReader()
        with monitor_for(reader, recorder):
            assert not recorder.tags
            reader.present(FakeNTAG213(uid=UID_A))
            assert recorder.wait()
        assert recorder.tags == [UID_A]

    def test_removal_is_reported_with_the_uid(self, reader, recorder):
        with monitor_for(reader, recorder):
            assert recorder.wait()
            reader.remove()
            assert recorder.wait(2)
        assert recorder.removed == [UID_A]

    def test_removal_is_reported_once(self, reader, recorder):
        with monitor_for(reader, recorder, debounce=10):
            assert recorder.wait()
            reader.remove()
            assert recorder.wait(2)
        assert recorder.removed.count(UID_A) == 1

    def test_an_empty_reader_reports_nothing(self, recorder):
        reader = FakeReader()
        with monitor_for(reader, recorder):
            pass
        assert recorder.tags == []
        assert recorder.removed == []

    def test_a_different_tag_is_reported_even_inside_the_debounce(self, reader, recorder):
        with monitor_for(reader, recorder, debounce=60):
            assert recorder.wait()
            reader.present(FakeNTAG213(uid=UID_B))
            assert recorder.wait(2)
        assert UID_B in recorder.tags

    def test_callbacks_are_optional(self, reader):
        with Monitor(reader, poll_interval=0.01):
            pass


class TestDebounce:
    def test_a_parked_tag_is_reported_once(self, reader, recorder):
        # The point of the debounce: a tag left on the reader must not fire on
        # every single tick.
        with monitor_for(reader, recorder, debounce=60):
            assert recorder.wait()
            for _ in range(20):
                reader.wait_for_change(0.001)
        assert recorder.tags == [UID_A]

    def test_zero_debounce_reports_every_time(self, reader, recorder):
        with monitor_for(reader, recorder, debounce=0):
            assert recorder.wait(3)
        assert len(recorder.tags) >= 3

    def test_forget_lets_a_tag_be_reported_again(self, reader, recorder):
        monitor = monitor_for(reader, recorder, debounce=60)
        with monitor:
            assert recorder.wait()
            monitor.forget(UID_A)
            assert recorder.wait(2)
        assert recorder.tags == [UID_A, UID_A]

    def test_forget_with_no_uid_clears_everything(self, reader, recorder):
        monitor = monitor_for(reader, recorder, debounce=60)
        with monitor:
            assert recorder.wait()
            monitor.forget()
            assert recorder.wait(2)
        assert len(recorder.tags) == 2


class TestErrors:
    def test_a_failing_read_does_not_kill_the_thread(self, reader, recorder):
        monitor = monitor_for(reader, recorder)
        calls = {"n": 0}
        real_current_tag = reader.current_tag

        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise CardRemoved("pulled off mid-exchange")
            return real_current_tag()

        reader.current_tag = flaky
        with monitor:
            assert recorder.wait(2)
            assert monitor.is_running

        assert len(recorder.errors) == 1
        assert recorder.tags == [UID_A]

    def test_errors_are_swallowed_when_nobody_is_listening(self, reader):
        monitor = Monitor(reader, poll_interval=0.01)
        reader.current_tag = lambda: (_ for _ in ()).throw(CardRemoved("gone"))
        with monitor:
            reader.wait_for_change(0.05)
            assert monitor.is_running
