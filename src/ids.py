"""
Pluggable IDS integration.

Runs a real IDS engine (Suricata, Snort, or Zeek) as a subprocess on the
attacker machine, tails its log output in real time, and exposes a uniform
stream of alerts to the rest of the tool. The AI analyst and the adaptive
controller consume these alerts to reason about detection.
"""

import os
import json
import time
import select
import subprocess
import threading
from typing import List, Dict, Optional
from dataclasses import dataclass
from rich.console import Console

console = Console()


@dataclass
class IDSAlert:
    """A normalized IDS signature alert, engine-agnostic."""
    timestamp: str
    signature_id: int
    signature: str
    category: str
    severity: int
    src_ip: str
    dst_ip: str
    dst_port: int
    raw_json: str
    rule_logic: str
    engine: str


SuricataAlert = IDSAlert


class IDSAgent:
    """Base class with shared alert storage, tailing helpers, and lifecycle."""

    engine = "ids"

    def __init__(self, target: str, iface: str):
        self.target = target
        self.iface = iface

        src_dir = os.path.dirname(os.path.abspath(__file__))
        self.log_dir = os.path.join(src_dir, "logs")
        self.rule_files: List[str] = []

        self.alerts: List[IDSAlert] = []
        self._lock = threading.Lock()
        self.stats = {"events_parsed": 0, "alerts_fired": 0, "last_rule": "None"}

        self._proc: Optional[subprocess.Popen] = None
        self._running = False
        self._tail_thread: Optional[threading.Thread] = None

    def start(self, use_custom_rules: bool = False) -> bool:
        raise NotImplementedError

    def wait_for_ready(self, extra_timeout: float = 120.0) -> bool:
        return False

    def stop(self):
        self._running = False
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def get_new_alerts(self) -> List[IDSAlert]:
        with self._lock:
            batch = list(self.alerts)
            self.alerts.clear()
            return batch

    def _add_alert(self, alert: IDSAlert):
        with self._lock:
            self.alerts.append(alert)
            self.stats["alerts_fired"] += 1
            self.stats["last_rule"] = alert.signature

    def _lookup_rule(self, sid: int) -> str:
        if not sid:
            return "Rule logic unavailable."
        for rf in self.rule_files:
            if not os.path.exists(rf):
                continue
            try:
                with open(rf, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if f"sid:{sid};" in line:
                            return line.strip()
            except OSError:
                continue
        return "Rule logic unavailable."

    def _tail_json_lines(self, path: str, handler):
        """Tail a JSON-lines log, dispatching each parsed record to handler."""
        while self._running:
            if not os.path.exists(path):
                time.sleep(0.5)
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(0, os.SEEK_END)
                while self._running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    self.stats["events_parsed"] += 1
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    handler(record)


class SuricataAgent(IDSAgent):
    """Suricata in interface mode, tailing eve.json for alert events."""

    engine = "suricata"

    _READY_MARKERS = (
        "Engine started.",
        "engine started",
        "all 1 packet processing threads",
        "packet processing threads started",
    )

    def __init__(self, target: str, iface: str):
        super().__init__(target, iface)
        self.eve_log = os.path.join(self.log_dir, "eve.json")
        self.rule_files = [
            os.path.join(self.log_dir, "custom.rules"),
            "/var/lib/suricata/rules/suricata.rules",
        ]

    def start(self, use_custom_rules: bool = False) -> bool:
        os.makedirs(self.log_dir, exist_ok=True)
        custom_rules_path = os.path.join(self.log_dir, "custom.rules")
        main_rules = "/var/lib/suricata/rules/suricata.rules"

        if use_custom_rules:
            rules = [
                'alert tcp any any -> any any (msg:"IDS: Rapid SYN Scan Activity (High-Rate)"; flags:S; detection_filter:track by_src, count 30, seconds 5; sid:1000001; rev:3;)',
                'alert tcp any any -> any any (msg:"IDS: Potential Stealth Port Scan Detected"; flags:S; ack:0; window:1024; detection_filter:track by_src, count 10, seconds 30; sid:1000002; rev:3;)',
                'alert tcp any any -> any any (msg:"IDS: OS Fingerprinting Attempt Detected"; flags:S; ttl:64; window:1024; sid:1000003; rev:3;)',
            ]
            with open(custom_rules_path, "w", encoding="utf-8") as f:
                f.write("\n".join(rules) + "\n")

        if os.path.exists(self.eve_log):
            try:
                os.remove(self.eve_log)
            except OSError:
                pass

        cmd = [
            "suricata", "-i", self.iface,
            "-l", self.log_dir,
            "-k", "none",
            "--set", "outputs.1.eve-log.enabled=yes",
            "--set", "outputs.1.eve-log.filetype=regular",
        ]

        if use_custom_rules:
            combined = os.path.join(self.log_dir, "combined.rules")
            with open(combined, "w", encoding="utf-8") as out:
                if os.path.exists(custom_rules_path):
                    with open(custom_rules_path, "r", encoding="utf-8") as f:
                        out.write(f.read())
                if os.path.exists(main_rules):
                    with open(main_rules, "r", errors="ignore") as f:
                        out.write(f.read())
            cmd.extend(["-S", combined])
        elif os.path.exists(main_rules):
            cmd.extend(["-S", main_rules])
        else:
            console.print("  [yellow]No rule files found! Suricata will run with defaults.[/yellow]")

        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
            )
        except FileNotFoundError:
            console.print("  [bold red]Suricata binary not found on PATH.[/bold red]")
            return False
        self._running = True

        max_wait = 60.0
        start_time = time.time()
        console.print("\n  [blue]Waiting for Suricata IDS to finish loading rules ...[/blue]")
        ready = self._poll_engine_ready(max_wait)

        if self._proc.poll() is not None:
            remaining_err = self._proc.stderr.read()
            console.print("\n  [bold red]Suricata failed to start![/bold red]")
            console.print(f"  [dim]{remaining_err.strip()}[/dim]\n")
            self._running = False
            return False

        elapsed = time.time() - start_time
        if ready:
            console.print(f"  [green]Suricata IDS ready ({elapsed:.1f}s) — rules loaded, capturing traffic[/green]")
        else:
            console.print(f"  [yellow]Suricata readiness signal not received within {max_wait:.0f}s[/yellow]")

        self._tail_thread = threading.Thread(
            target=self._tail_json_lines, args=(self.eve_log, self._handle_record), daemon=True
        )
        self._tail_thread.start()
        return ready

    def _poll_engine_ready(self, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._proc.poll() is not None:
                return False
            rlist, _, _ = select.select([self._proc.stderr], [], [], 0.2)
            if rlist:
                line = self._proc.stderr.readline()
                if line and any(m in line for m in self._READY_MARKERS):
                    return True
            if os.path.exists(self.eve_log) and os.path.getsize(self.eve_log) > 0:
                return True
        return False

    def wait_for_ready(self, extra_timeout: float = 120.0) -> bool:
        if not self._running or self._proc.poll() is not None:
            return False
        return self._poll_engine_ready(extra_timeout)

    def _handle_record(self, record: dict):
        if record.get("event_type") != "alert":
            return
        alert_info = record.get("alert", {})
        sid = alert_info.get("signature_id", 0)
        self._add_alert(IDSAlert(
            timestamp=record.get("timestamp", ""),
            signature_id=sid,
            signature=alert_info.get("signature", "Unknown"),
            category=alert_info.get("category", ""),
            severity=alert_info.get("severity", 0),
            src_ip=record.get("src_ip", ""),
            dst_ip=record.get("dest_ip", ""),
            dst_port=record.get("dest_port", 0),
            raw_json=json.dumps(record),
            rule_logic=self._lookup_rule(sid),
            engine=self.engine,
        ))


class SnortAgent(IDSAgent):
    """Snort 3 in interface mode, tailing JSON alerts (-A json)."""

    engine = "snort"

    def __init__(self, target: str, iface: str, config: Optional[str] = None):
        super().__init__(target, iface)
        self.config = config
        self.alert_log = os.path.join(self.log_dir, "alert_json.txt")

    def start(self, use_custom_rules: bool = False) -> bool:
        os.makedirs(self.log_dir, exist_ok=True)
        if os.path.exists(self.alert_log):
            try:
                os.remove(self.alert_log)
            except OSError:
                pass

        cmd = ["snort", "-i", self.iface, "-l", self.log_dir, "-A", "json", "-q"]
        if self.config:
            cmd.extend(["-c", self.config])
            self.rule_files = [self.config]
        else:
            console.print("  [yellow]No Snort config provided (ids.snort_config) — alerts may be empty.[/yellow]")

        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
            )
        except FileNotFoundError:
            console.print("  [bold red]Snort binary not found on PATH.[/bold red]")
            return False
        self._running = True

        ready = self._wait_for_log(20.0)
        if self._proc.poll() is not None:
            err = self._proc.stderr.read()
            console.print("\n  [bold red]Snort failed to start![/bold red]")
            console.print(f"  [dim]{err.strip()}[/dim]\n")
            self._running = False
            return False

        self._tail_thread = threading.Thread(
            target=self._tail_json_lines, args=(self.alert_log, self._handle_record), daemon=True
        )
        self._tail_thread.start()
        if ready:
            console.print("  [green]Snort IDS ready — capturing traffic[/green]")
        return True

    def _wait_for_log(self, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._proc.poll() is not None:
                return False
            if os.path.exists(self.alert_log):
                return True
            time.sleep(0.3)
        return True

    def _handle_record(self, record: dict):
        sid = record.get("sid") or record.get("signature_id") or 0
        self._add_alert(IDSAlert(
            timestamp=str(record.get("seconds", record.get("timestamp", ""))),
            signature_id=int(sid),
            signature=record.get("msg", "Unknown"),
            category=record.get("class", record.get("priority", "")),
            severity=int(record.get("priority", 0) or 0),
            src_ip=record.get("src_addr", record.get("src_ip", "")),
            dst_ip=record.get("dst_addr", record.get("dst_ip", "")),
            dst_port=int(record.get("dst_port", 0) or 0),
            raw_json=json.dumps(record),
            rule_logic=self._lookup_rule(int(sid)),
            engine=self.engine,
        ))


class ZeekAgent(IDSAgent):
    """Zeek in interface mode, tailing notice.log (TSV) for notices."""

    engine = "zeek"

    def __init__(self, target: str, iface: str, scripts: Optional[List[str]] = None):
        super().__init__(target, iface)
        self.scripts = scripts or []
        self.notice_log = os.path.join(self.log_dir, "notice.log")

    def start(self, use_custom_rules: bool = False) -> bool:
        os.makedirs(self.log_dir, exist_ok=True)
        if os.path.exists(self.notice_log):
            try:
                os.remove(self.notice_log)
            except OSError:
                pass

        cmd = ["zeek", "-i", self.iface] + self.scripts
        try:
            self._proc = subprocess.Popen(
                cmd, cwd=self.log_dir,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
            )
        except FileNotFoundError:
            console.print("  [bold red]Zeek binary not found on PATH.[/bold red]")
            return False
        self._running = True

        time.sleep(2.0)
        if self._proc.poll() is not None:
            err = self._proc.stderr.read()
            console.print("\n  [bold red]Zeek failed to start![/bold red]")
            console.print(f"  [dim]{err.strip()}[/dim]\n")
            self._running = False
            return False

        self._tail_thread = threading.Thread(target=self._tail_notice, daemon=True)
        self._tail_thread.start()
        console.print("  [green]Zeek IDS ready — capturing traffic[/green]")
        return True

    def _tail_notice(self):
        fields: List[str] = []
        while self._running:
            if not os.path.exists(self.notice_log):
                time.sleep(0.5)
                continue
            with open(self.notice_log, "r", encoding="utf-8", errors="ignore") as f:
                while self._running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    line = line.rstrip("\n")
                    if line.startswith("#fields"):
                        fields = line.split("\t")[1:]
                        continue
                    if line.startswith("#") or not line:
                        continue
                    self.stats["events_parsed"] += 1
                    self._handle_notice(fields, line.split("\t"))

    def _handle_notice(self, fields: List[str], values: List[str]):
        if not fields:
            return
        row = dict(zip(fields, values))
        self._add_alert(IDSAlert(
            timestamp=row.get("ts", ""),
            signature_id=0,
            signature=row.get("note", "Zeek::Notice"),
            category=row.get("msg", ""),
            severity=0,
            src_ip=row.get("id.orig_h", row.get("src", "")),
            dst_ip=row.get("id.resp_h", row.get("dst", "")),
            dst_port=int(row.get("id.resp_p", 0) or 0),
            raw_json=json.dumps(row),
            rule_logic="Zeek notice (no signature SID).",
            engine=self.engine,
        ))


def make_ids(engine: str, target: str, iface: str, cfg: Optional[dict] = None) -> IDSAgent:
    """Factory: build the requested IDS backend."""
    cfg = cfg or {}
    engine = (engine or "suricata").lower()
    if engine == "snort":
        return SnortAgent(target, iface, config=cfg.get("snort_config"))
    if engine == "zeek":
        return ZeekAgent(target, iface, scripts=cfg.get("zeek_scripts", []))
    return SuricataAgent(target, iface)
