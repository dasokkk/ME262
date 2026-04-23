"""
Suricata IDS Agent - Real-world enterprise IDS integration.

Runs Suricata as a subprocess on the attacker machine, dumping logs
to a temporary directory. A Python thread tails `eve.json` in real-time
and feeds world-class signature detections to the AI model.
"""
import re
import os
import json
import time
import subprocess
import threading
from typing import List, Dict, Optional
from dataclasses import dataclass
from rich.console import Console

console = Console()


@dataclass
class SuricataAlert:
    """A Suricata signature alert generated from real traffic."""
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


class SuricataAgent:
    
     
     
     
    
    def __init__(self, target: str, iface: str):
        self.target = target
        self.iface = iface
        
         
        src_dir = os.path.dirname(os.path.abspath(__file__))
        self.log_dir = os.path.join(src_dir, "logs")
        self.eve_log = os.path.join(self.log_dir, "eve.json")
        
        self.rule_files = [
            os.path.join(self.log_dir, "custom.rules"),
            "/var/lib/suricata/rules/suricata.rules"
        ]
        self.alerts: List[SuricataAlert] = []
        self._lock = threading.Lock()
        
         
        self.stats = {"events_parsed": 0, "alerts_fired": 0, "last_rule": "None"}
        
        self._suricata_proc = None
        self._running = False
        self._tail_thread = None

    def start(self, use_custom_rules: bool = False):
        os.makedirs(self.log_dir, exist_ok=True)
        custom_rules_path = os.path.join(self.log_dir, "custom.rules")
        
        if use_custom_rules:
            # Create a highly sensitive custom ruleset for testing (Mimics Expert IDS logic)
            rules = [
                'alert tcp any any -> any any (msg:"IDS: Rapid SYN Scan Activity (High-Rate)"; flags:S; detection_filter:track by_src, count 30, seconds 5; sid:1000001; rev:3;)',
                'alert tcp any any -> any any (msg:"IDS: Potential Stealth Port Scan Detected"; flags:S; ack:0; window:1024; detection_filter:track by_src, count 10, seconds 30; sid:1000002; rev:3;)',
                'alert tcp any any -> any any (msg:"IDS: OS Fingerprinting Attempt Detected"; flags:S; ttl:64; window:1024; sid:1000003; rev:3;)'
            ]
            with open(custom_rules_path, "w") as f:
                f.write("\n".join(rules) + "\n")

        
        if os.path.exists(self.eve_log):
            try: os.remove(self.eve_log)
            except: pass
            
         
        main_rules = "/var/lib/suricata/rules/suricata.rules"
        
        cmd = [
            "suricata", "-i", self.iface, 
            "-l", self.log_dir,
            "-k", "none",
            "--set", "outputs.1.eve-log.enabled=yes",
            "--set", "outputs.1.eve-log.filetype=regular"
        ]
        
        if use_custom_rules:
            
            cmd.extend(["-S", custom_rules_path])
            if os.path.exists(main_rules):
                cmd.extend(["-s", main_rules])
        else:
             
            if os.path.exists(main_rules):
                cmd.extend(["-S", main_rules])
            else:
                 
                print("  [yellow]⚠  No rule files found! Suricata will run with defaults.[/yellow]")

         
        self._suricata_proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
        )
        self._running = True
        
         
        wait_time = 20.0 if os.path.exists(main_rules) else 3.0
        console.print(f"\n  [blue]Waiting for Suricata IDS to load rules ({int(wait_time)}s)[/blue]")
        time.sleep(wait_time) 
        
        # CHECK IF SURICATA CRASHED
        if self._suricata_proc.poll() is not None:
            err = self._suricata_proc.stderr.read()
            print(f"\n  [bold red]✖  Suricata failed to start![/bold red]")
            print(f"  [dim]{err}[/dim]\n")
            self._running = False
            return
        
        self._tail_thread = threading.Thread(target=self._tail_eve_json, daemon=True)
        self._tail_thread.start()

    def _tail_eve_json(self):
         
        while self._running:
            if not os.path.exists(self.eve_log):
                time.sleep(0.5)
                continue
                
            with open(self.eve_log, "r") as f:
                 
                f.seek(0, os.SEEK_END)
                
                while self._running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    
                    self.stats["events_parsed"] += 1
                    try:
                        record = json.loads(line)
                        if record.get("event_type") == "alert":
                            self._handle_alert(record)
                    except json.JSONDecodeError:
                        pass

    def _handle_alert(self, record):
        dst_ip = record.get("dest_ip", "")
        alert_info = record.get("alert", {})
        sid = alert_info.get("signature_id", 0)
        
       
        rule_logic = "Rule logic unavailable."
        if sid:
            for rf in self.rule_files:
                if os.path.exists(rf):
                    try:
                        with open(rf, 'r', encoding='utf-8', errors='ignore') as f:
                            for r_line in f:
                                if f"sid:{sid};" in r_line:
                                    rule_logic = r_line.strip()
                                    break
                        if rule_logic != "Rule logic unavailable.":
                            break
                    except Exception:
                        pass
        
        alert = SuricataAlert(
            timestamp=record.get("timestamp", ""),
            signature_id=sid,
            signature=alert_info.get("signature", "Unknown"),
            category=alert_info.get("category", ""),
            severity=alert_info.get("severity", 0),
            src_ip=record.get("src_ip", ""),
            dst_ip=dst_ip,
            dst_port=record.get("dest_port", 0),
            raw_json=json.dumps(record),
            rule_logic=rule_logic
        )
        
        with self._lock:
            self.alerts.append(alert)
            self.stats["alerts_fired"] += 1
            self.stats["last_rule"] = alert.signature

    def get_new_alerts(self) -> List[SuricataAlert]:
       
        with self._lock:
            batch = list(self.alerts)
            self.alerts.clear()
            return batch

    def stop(self):
       
        self._running = False
        if self._suricata_proc:
            self._suricata_proc.terminate()
            self._suricata_proc.wait()
