"""
Uses the local Ollama HTTP API to analyse IDS detections, communicate
with the user, and translate natural-language instructions into
scanner parameter adjustments.

Handles auto-starting Ollama and auto-pulling models.
"""

import json
import re
import subprocess
import time
import shutil
import threading
import requests
from typing import Dict, List, Optional, Callable

SYSTEM_PROMPT = """\
You are a cybersecurity AI analyst embedded in a live network-scanning and
IDS-simulation system.  You speak directly with the operator.

Your responsibilities:
1. When the IDS detects suspicious scanning activity you ANALYSE the
   detection and explain it clearly and concisely.
2. You discuss findings with the operator and recommend next steps.
3. Based on operator instructions you decide how to adjust the scanner
   parameters and output them as a fenced JSON block.

Adjustable scanner parameters (include ONLY the ones you want to change):
  scan_rate      : float   – probes per second  (e.g. 1.0, 5.0, 20.0)
  port_strategy  : string  – "top" | "random" | "sequential" | "weighted"
  timing_model   : string  – "fixed" | "jitter" | "burst" | "longtail"
  timeout        : float   – per-probe timeout in seconds (e.g. 0.5, 1.0)
  scan_type      : string  – "tcp_connect" | "http_probe"

When you decide on changes, output them inside a fenced JSON block:
```json
{"scan_rate": 2.0, "timing_model": "jitter"}
```

Be conversational, concise, and technical.  Always explain your reasoning.
"""


class AIController:
    

    def __init__(self, model: str = "llama3.2",
                 base_url: str = "http://localhost:11434",
                 chat_timeout: int = 600,
                 log_fn: Optional[Callable] = None):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.chat_timeout = chat_timeout
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        self._log = log_fn or (lambda msg: None)
        self.available = False       
        self._ollama_proc = None      

    # Ollama lifecycle

    @staticmethod
    def is_ollama_installed() -> bool:
         
        return shutil.which("ollama") is not None

    def is_ollama_running(self) -> bool:
        
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def start_ollama(self) -> bool:
        
        if self.is_ollama_running():
            return True
        try:
            self._log("Starting Ollama in the background …")
            self._ollama_proc = subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
                
            for _ in range(30):             
                time.sleep(0.5)
                if self.is_ollama_running():
                    self._log("Ollama is running ✓")
                    return True
            self._log("Ollama did not start in time.")
            return False
        except FileNotFoundError:
            return False
        except Exception as exc:
            self._log(f"Error starting Ollama: {exc}")
            return False

    def get_available_models(self):
            
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=3)
            if r.status_code == 200:
                data = r.json()
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            pass
        return []

    def model_exists(self) -> bool:
            
        models = self.get_available_models()
        return any(self.model in m for m in models)

    def pull_model(self, progress_fn: Optional[Callable] = None) -> bool:
            
        self._log(f"Pulling model '{self.model}' — this may take a few minutes …")
        try:
            r = requests.post(
                f"{self.base_url}/api/pull",
                json={"name": self.model, "stream": True},
                stream=True,
                timeout=600,
            )
            if r.status_code != 200:
                self._log(f"Pull failed: HTTP {r.status_code}")
                return False

            for line in r.iter_lines():
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    status = data.get("status", "")
                        
                    total = data.get("total", 0)
                    completed = data.get("completed", 0)
                    if progress_fn and total > 0:
                        progress_fn(status, completed, total)
                    elif progress_fn:
                        progress_fn(status, 0, 0)
                except json.JSONDecodeError:
                    pass

            self._log(f"Model '{self.model}' pulled ✓")
            return True
        except Exception as exc:
            self._log(f"Pull error: {exc}")
            return False

    def ensure_ready(self, progress_fn: Optional[Callable] = None) -> bool:
        
        if not self.is_ollama_installed():
            self._log(
                "Ollama is not installed.\n"
                "  Install:  curl -fsSL https://ollama.com/install.sh | sh"
            )
            return False

        # 2. server running?
        if not self.is_ollama_running():
            if not self.start_ollama():
                self._log("Could not start Ollama.")
                return False

        # 3. model pulled?
        if not self.model_exists():
            if not self.pull_model(progress_fn):
                self._log(f"Could not pull model '{self.model}'.")
                return False

        self.available = True
        return True

     

    MAX_HISTORY = 20

    def _trim_history(self):
        """Keep system prompt + most recent MAX_HISTORY messages."""
        system = [m for m in self.messages if m["role"] == "system"]
        turns  = [m for m in self.messages if m["role"] != "system"]
        if len(turns) > self.MAX_HISTORY:
            turns = turns[-self.MAX_HISTORY:]
        self.messages = system + turns

    def _chat(self, user_content: str, stream_fn: Callable = None) -> str:
        """Send a message and return the full reply.

        If stream_fn is provided it is called with each text chunk as it
        arrives, so the UI can print tokens in real-time instead of waiting
        for the whole response.
        """
        self.messages.append({"role": "user", "content": user_content})
        self._trim_history()

        try:
            r = requests.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": self.messages,
                    "stream": True,          # always stream — avoids long silent wait
                },
                stream=True,
                timeout=self.chat_timeout,
            )
            if r.status_code != 200:
                return f"[Ollama HTTP {r.status_code}] {r.text[:200]}"

            full_reply = []
            for raw_line in r.iter_lines():
                if not raw_line:
                    continue
                try:
                    chunk = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                token = chunk.get("message", {}).get("content", "")
                if token:
                    full_reply.append(token)
                    if stream_fn:
                        stream_fn(token)
                if chunk.get("done"):
                    break

            reply = "".join(full_reply)
            self.messages.append({"role": "assistant", "content": reply})
            return reply

        except requests.ConnectionError:
            return "[AI Offline] Cannot reach Ollama. Is it running?"
        except requests.ReadTimeout:
            return (
                "[AI Timeout] Model took too long to respond. "
                "Try increasing 'timeout' in config.json or use a smaller model."
            )
        except Exception as exc:
            return f"[AI Error] {exc}"

     

    def analyze_suricata_alerts(self, alerts: List, scanner_params: Dict,
                                stream_fn: Callable = None) -> str:
        # Deduplicate: group by signature_id to avoid sending dozens of identical
        # alert blocks when the same rule fires repeatedly (wastes tokens, slows response).
        seen: Dict[int, dict] = {}
        for alert in alerts:
            if alert.signature_id not in seen:
                seen[alert.signature_id] = {
                    "signature": alert.signature,
                    "category":  alert.category,
                    "rule_logic": alert.rule_logic,
                    "ports": [],
                }
            seen[alert.signature_id]["ports"].append(alert.dst_port)

        prompt = f"🚨 SURICATA DETECTIONS ({len(alerts)} alerts, {len(seen)} unique signatures)\n"
        for sid, info in seen.items():
            ports_str = ", ".join(str(p) for p in sorted(set(info["ports"]))[:10])
            if len(info["ports"]) > 10:
                ports_str += f" … (+{len(info['ports'])-10} more)"
            prompt += (
                f"\n[SID {sid}] {info['signature']}\n"
                f"  Category  : {info['category']}\n"
                f"  Ports hit : {ports_str}\n"
                f"  Rule      : {info['rule_logic']}\n"
            )

        prompt += (
            f"\nScanner params: {json.dumps(scanner_params)}\n\n"
            "Brief analysis: what triggered these, why, and top 2 evasion options."
        )
        return self._chat(prompt, stream_fn=stream_fn)


    def process_user_input(self, user_input: str,
                           scanner_params: Dict) -> str:
         
        prompt = (
            f'The operator says: "{user_input}"\n\n'
            f"Current scanner parameters:\n"
            f"{json.dumps(scanner_params, indent=2)}\n\n"
            "Based on the operator's instruction, decide what parameter "
            "changes to make (if any). Output your reasoning, then "
            "provide the changes inside a ```json``` block."
        )
        return self._chat(prompt)

     

    @staticmethod
    def extract_params(ai_response: str) -> Dict:
         
        valid_keys = {
            "scan_rate", "port_strategy", "timing_model",
            "timeout", "scan_type",
        }
        match = re.search(
            r"```(?:json)?\s*\n?(.*?)\n?\s*```", ai_response, re.DOTALL
        )
        if match:
            try:
                raw = json.loads(match.group(1))
                return {k: v for k, v in raw.items() if k in valid_keys}
            except (json.JSONDecodeError, AttributeError):
                pass
        return {}