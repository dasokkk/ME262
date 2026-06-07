"""
Persistent evasion memory.

Records which scanner parameter sets triggered which IDS signatures across
runs, then surfaces a compact summary the AI analyst can learn from and the
quietest known configuration to seed future scans.
"""

import json
import os
import time
from typing import Dict, List, Optional

TRACKED_KEYS = (
    "scan_rate", "port_strategy", "timing_model", "timeout",
    "spoof_app", "full_connect", "ssl_scan", "mtu", "source_port",
    "ttl", "badsum", "proxy", "decoys",
)


class EvasionMemory:
    """A small JSON-backed log of (params -> detected signatures) outcomes."""

    def __init__(self, path: str):
        self.path = path
        self.entries: List[dict] = []
        self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                self.entries = data
        except (json.JSONDecodeError, OSError):
            self.entries = []

    def _save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.entries, f, indent=2)
        except OSError:
            pass

    def record(self, params: Dict, sids: List[int], detected: bool, target: str = ""):
        self.entries.append({
            "ts": time.time(),
            "target": target,
            "params": {k: params.get(k) for k in TRACKED_KEYS},
            "sids": sorted({int(s) for s in sids}),
            "detected": bool(detected),
        })
        self._save()

    def best_known(self) -> Optional[Dict]:
        """Return params from the most recent undetected run, if any."""
        for entry in reversed(self.entries):
            if not entry["detected"]:
                return entry["params"]
        return None

    def summary_for_prompt(self, limit: int = 8) -> str:
        if not self.entries:
            return "Evasion history: none yet."
        recent = self.entries[-limit:]
        lines = [f"Evasion history ({len(self.entries)} runs, last {len(recent)}):"]
        for entry in recent:
            p = entry["params"]
            verdict = "DETECTED" if entry["detected"] else "clean"
            sids = ", ".join(str(s) for s in entry["sids"][:5]) or "none"
            lines.append(
                f"  rate={p.get('scan_rate')} timing={p.get('timing_model')} "
                f"mtu={p.get('mtu')} spoof_app={p.get('spoof_app')} "
                f"full_connect={p.get('full_connect')} -> {verdict} (sids: {sids})"
            )
        return "\n".join(lines)
