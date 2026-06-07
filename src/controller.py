"""
Adaptive evasion controller.

Tracks the live detection rate (alerts divided by probes over a sliding
window) and, when it crosses a threshold, walks an escalating ladder of
stealth adjustments. Used both as the no-AI fallback and as the engine behind
auto-evade search mode.
"""

import time
from collections import deque
from typing import Dict, List, Optional, Tuple


class RateTracker:
    """Sliding-window counter for probes and alerts to derive a detection rate."""

    def __init__(self, window: float = 10.0):
        self.window = window
        self._probes: deque = deque()
        self._alerts: deque = deque()

    def record_probe(self, n: int = 1):
        now = time.time()
        self._probes.extend([now] * n)
        self._trim(now)

    def record_alert(self, n: int = 1):
        now = time.time()
        self._alerts.extend([now] * n)
        self._trim(now)

    def _trim(self, now: float):
        cutoff = now - self.window
        while self._probes and self._probes[0] < cutoff:
            self._probes.popleft()
        while self._alerts and self._alerts[0] < cutoff:
            self._alerts.popleft()

    def rate(self) -> float:
        self._trim(time.time())
        probes = len(self._probes)
        if probes == 0:
            return 1.0 if self._alerts else 0.0
        return min(1.0, len(self._alerts) / probes)


class AdaptiveController:
    """Escalating ladder of evasion steps applied when detection is too high."""

    def __init__(self, proxy: Optional[str] = None):
        self.step = 0
        self.proxy = proxy
        self._ladder = self._build_ladder()

    def _build_ladder(self) -> List[Tuple[str, Dict]]:
        ladder: List[Tuple[str, Dict]] = [
            ("Halving scan rate and adding timing jitter",
             {"scan_rate": "half", "timing_model": "jitter"}),
            ("Switching to long-tail timing with a longer timeout",
             {"timing_model": "longtail", "timeout": 2.0}),
            ("Fragmenting packets (MTU 16) to break signatures",
             {"mtu": 16}),
            ("Randomizing source port and spoofing app-layer payloads",
             {"source_port": None, "spoof_app": True}),
            ("Spreading probes across random high ports",
             {"port_strategy": "random"}),
            ("Dropping to a stealth crawl",
             {"scan_rate": "quarter", "timing_model": "longtail"}),
        ]
        if self.proxy:
            ladder.append(("Routing through proxy for IP rotation",
                           {"proxy": self.proxy}))
        else:
            ladder.append(("Completing full TCP handshakes to blend in",
                           {"full_connect": True}))
        return ladder

    def next_step(self, current: Dict) -> Optional[Tuple[str, Dict]]:
        """Return (description, param_changes) for the next rung, or None."""
        if self.step >= len(self._ladder):
            return None
        desc, raw = self._ladder[self.step]
        self.step += 1

        base_rate = float(current.get("scan_rate", 3.0) or 3.0)
        changes: Dict = {}
        for key, value in raw.items():
            if value == "half":
                changes[key] = max(0.1, base_rate / 2.0)
            elif value == "quarter":
                changes[key] = max(0.05, base_rate / 4.0)
            else:
                changes[key] = value
        return desc, changes

    def exhausted(self) -> bool:
        return self.step >= len(self._ladder)
