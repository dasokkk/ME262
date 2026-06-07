"""
Session reporting.

Collects open ports, IDS alerts, and parameter changes during a run, then
exports JSON/CSV and produces an after-action evasion debrief that correlates
the techniques in use with the detections that fired.
"""

import csv
import json
import time
from typing import Dict, List

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1723: "pptp",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    8888: "sun-answerbook", 9090: "zeus-admin", 11434: "ollama",
    27017: "mongodb",
}


def service_name(port: int) -> str:
    return SERVICES.get(port, "unknown")


class SessionReporter:
    """Aggregates results across one or more targets for export and debrief."""

    def __init__(self, targets: List[str]):
        self.targets = targets
        self.started = time.time()
        self.open_ports: Dict[str, List[int]] = {}
        self.banners: Dict[str, Dict[int, str]] = {}
        self.alerts: List[dict] = []
        self.param_changes: List[dict] = []
        self.total_probes = 0

    def record_open(self, target: str, port: int, banner: str = ""):
        ports = self.open_ports.setdefault(target, [])
        if port not in ports:
            ports.append(port)
        if banner:
            self.banners.setdefault(target, {})[port] = banner

    def record_alert(self, alert):
        self.alerts.append({
            "ts": time.time(),
            "signature_id": alert.signature_id,
            "signature": alert.signature,
            "category": alert.category,
            "dst_ip": alert.dst_ip,
            "dst_port": alert.dst_port,
            "engine": getattr(alert, "engine", "ids"),
        })

    def record_param_change(self, params: Dict, source: str):
        self.param_changes.append({
            "ts": time.time(),
            "source": source,
            "params": params,
        })

    def as_dict(self) -> Dict:
        return {
            "targets": self.targets,
            "started": self.started,
            "duration_s": round(time.time() - self.started, 1),
            "total_probes": self.total_probes,
            "open_ports": {t: sorted(set(p)) for t, p in self.open_ports.items()},
            "banners": self.banners,
            "alerts": self.alerts,
            "param_changes": self.param_changes,
        }

    def export_json(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.as_dict(), f, indent=2)

    def export_csv(self, path: str):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["target", "port", "service", "banner"])
            for target, ports in self.open_ports.items():
                for port in sorted(set(ports)):
                    banner = self.banners.get(target, {}).get(port, "")
                    w.writerow([target, port, service_name(port), banner])

    def after_action(self) -> Dict:
        return {
            "targets": len(self.targets),
            "total_probes": self.total_probes,
            "total_alerts": len(self.alerts),
            "unique_signatures": sorted({a["signature_id"] for a in self.alerts}),
            "adaptations": len(self.param_changes),
            "open_ports": {t: sorted(set(p)) for t, p in self.open_ports.items()},
        }
