"""Tests for ContextVar behaviour in the AWS linter plugin.

Proves that ``_wcu_limit_var`` works correctly in single-threaded usage
(set in main, read in main) and documents the isolation semantics: a
child thread does NOT inherit the value set in the parent thread.
"""

import threading

from octorules_aws.linter._plugin import _wcu_limit_var, set_wcu_limit


class TestWcuLimitSameThread:
    """ContextVar set+get in the same thread must round-trip."""

    def test_set_then_get(self):
        token = _wcu_limit_var.set(5000)
        try:
            assert _wcu_limit_var.get() == 5000
        finally:
            _wcu_limit_var.reset(token)

    def test_set_via_helper(self):
        """set_wcu_limit() is the public API; verify it writes the var."""
        # Save default first so we can restore
        orig = _wcu_limit_var.get()
        set_wcu_limit(5000)
        try:
            assert _wcu_limit_var.get() == 5000
        finally:
            # Restore — set_wcu_limit doesn't return a token, so use .set()
            _wcu_limit_var.set(orig)


class TestWcuLimitDefault:
    """Without calling set_wcu_limit, the default must be 1500."""

    def test_default_value(self):
        # Use a fresh thread so there's definitely no prior .set() call
        result = []

        def reader():
            result.append(_wcu_limit_var.get())

        t = threading.Thread(target=reader)
        t.start()
        t.join()

        assert result == [1500]


class TestWcuLimitThreadIsolation:
    """ContextVar is per-context: child threads do NOT inherit the parent value.

    This is by design — ``contextvars.ContextVar`` copies are opt-in.
    Our usage pattern (set in main thread, lint in main thread) is safe.
    A worker thread spawned after `set_wcu_limit()` sees the *default*,
    not the parent's override.
    """

    def test_child_thread_sees_default_not_parent_value(self):
        token = _wcu_limit_var.set(9999)
        try:
            child_value = []

            def reader():
                child_value.append(_wcu_limit_var.get())

            t = threading.Thread(target=reader)
            t.start()
            t.join()

            # Main thread still sees 9999
            assert _wcu_limit_var.get() == 9999
            # Child thread saw the default (1500), NOT 9999
            assert child_value == [1500]
        finally:
            _wcu_limit_var.reset(token)
