"""
AI controller.

Uses the local Ollama HTTP API to analyse IDS detections, talk with the
operator, and translate natural-language instructions into concrete scanner
parameter adjustments. Handles auto-starting Ollama and auto-pulling models.
"""

import json
import re
import subprocess
import time
import shutil
import requests
from typing import Dict, List, Optional, Callable

SYSTEM_PROMPT = """\
You are a cybersecurity AI analyst embedded in a live network-scanning and
IDS-monitoring system. You speak directly with the operator.

Your responsibilities:
1. When the IDS detects suspicious scanning activity you ANALYSE the detection
   and explain clearly and concisely what triggered it.
2. You discuss findings with the operator and recommend next steps.
3. Based on operator instructions you decide how to adjust scanner parameters
   and output them as a fenced JSON block.

Adjustable scanner parameters (include ONLY the ones you want to change):
  scan_rate     : float   - probes per second (e.g. 0.5, 3.0, 20.0)
  port_strategy : string  - "top" | "random" | "sequential" | "weighted"
  timing_model  : string  - "fixed" | "jitter" | "burst" | "longtail"
  timeout       : float   - per-probe timeout in seconds (e.g. 0.5, 2.0)
  source_port   : int     - fixed source port, or null for random
  spoof_app     : bool    - spoof HTTP/TLS/DNS app-layer payloads
  full_connect  : bool    - complete the TCP handshake (connect scan)
  ssl_scan      : bool    - perform real SSL/TLS handshakes on open ports
  mtu           : int     - fragment to this MTU (multiple of 8), or null to disable
  ttl           : int     - fixed IP TTL (1-255), or null for randomized
  badsum        : bool    - send a deliberately bad TCP checksum
  proxy         : string  - comma-separated proxy URLs, or null to disable
  decoys        : string  - comma-separated decoy IPs (use RND for random, ME for self)

When you decide on changes, output them inside a fenced JSON block:
```json
{"scan_rate": 0.5, "timing_model": "longtail", "mtu": 16}
```

Be conversational, concise, and technical. Always explain your reasoning.
"""

_STRING_CHOICES = {
    "port_strategy": {"top", "random", "sequential", "weighted"},
    "timing_model": {"fixed", "jitter", "burst", "longtail"},
}


def _clamp_float(value, lo, hi):
    try:
        return max(lo, min(hi, float(value)))
    except (TypeError, ValueError):
        return None


def validate_params(raw: Dict) -> Dict:
    """Coerce and validate an AI-proposed param dict into safe scanner values."""
    if not isinstance(raw, dict):
        return {}
    out: Dict = {}

    rate = _clamp_float(raw.get("scan_rate"), 0.05, 1000.0) if "scan_rate" in raw else None
    if rate is not None:
        out["scan_rate"] = rate

    timeout = _clamp_float(raw.get("timeout"), 0.05, 30.0) if "timeout" in raw else None
    if timeout is not None:
        out["timeout"] = timeout

    for key, choices in _STRING_CHOICES.items():
        if isinstance(raw.get(key), str) and raw[key] in choices:
            out[key] = raw[key]

    for key in ("spoof_app", "full_connect", "ssl_scan", "badsum"):
        if isinstance(raw.get(key), bool):
            out[key] = raw[key]

    if "source_port" in raw:
        sp = raw["source_port"]
        if sp is None:
            out["source_port"] = None
        else:
            try:
                sp = int(sp)
                if 1 <= sp <= 65535:
                    out["source_port"] = sp
            except (TypeError, ValueError):
                pass

    if "ttl" in raw:
        ttl = raw["ttl"]
        if ttl is None:
            out["ttl"] = None
        else:
            try:
                ttl = int(ttl)
                if 1 <= ttl <= 255:
                    out["ttl"] = ttl
            except (TypeError, ValueError):
                pass

    if "mtu" in raw:
        mtu = raw["mtu"]
        if mtu is None:
            out["mtu"] = None
        else:
            try:
                mtu = int(mtu)
                if mtu > 0 and mtu % 8 == 0:
                    out["mtu"] = mtu
            except (TypeError, ValueError):
                pass

    if "proxy" in raw:
        proxy = raw["proxy"]
        out["proxy"] = proxy if (isinstance(proxy, str) and proxy.strip()) else None

    if "decoys" in raw:
        decoys = raw["decoys"]
        if isinstance(decoys, str):
            out["decoys"] = [d.strip() for d in decoys.split(",") if d.strip()]
        elif isinstance(decoys, list):
            out["decoys"] = [str(d).strip() for d in decoys if str(d).strip()]

    return out


class AIController:

    MAX_HISTORY = 20

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

    @staticmethod
    def is_ollama_installed() -> bool:
        return shutil.which("ollama") is not None

    def is_ollama_running(self) -> bool:
        try:
            return requests.get(f"{self.base_url}/api/tags", timeout=3).status_code == 200
        except Exception:
            return False

    def start_ollama(self) -> bool:
        if self.is_ollama_running():
            return True
        try:
            self._log("Starting Ollama in the background ...")
            self._ollama_proc = subprocess.Popen(
                ["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            for _ in range(30):
                time.sleep(0.5)
                if self.is_ollama_running():
                    self._log("Ollama is running.")
                    return True
            self._log("Ollama did not start in time.")
            return False
        except FileNotFoundError:
            return False
        except Exception as exc:
            self._log(f"Error starting Ollama: {exc}")
            return False

    def get_available_models(self) -> List[str]:
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=3)
            if r.status_code == 200:
                return [m["name"] for m in r.json().get("models", [])]
        except Exception:
            pass
        return []

    def model_exists(self) -> bool:
        return any(self.model in m for m in self.get_available_models())

    def pull_model(self, progress_fn: Optional[Callable] = None) -> bool:
        self._log(f"Pulling model '{self.model}' — this may take a few minutes ...")
        try:
            r = requests.post(
                f"{self.base_url}/api/pull",
                json={"name": self.model, "stream": True}, stream=True, timeout=600,
            )
            if r.status_code != 200:
                self._log(f"Pull failed: HTTP {r.status_code}")
                return False
            for line in r.iter_lines():
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                status = data.get("status", "")
                total = data.get("total", 0)
                completed = data.get("completed", 0)
                if progress_fn:
                    progress_fn(status, completed, total)
            self._log(f"Model '{self.model}' pulled.")
            return True
        except Exception as exc:
            self._log(f"Pull error: {exc}")
            return False

    def ensure_ready(self, progress_fn: Optional[Callable] = None) -> bool:
        if not self.is_ollama_installed():
            self._log("Ollama is not installed. Install: curl -fsSL https://ollama.com/install.sh | sh")
            return False
        if not self.is_ollama_running() and not self.start_ollama():
            self._log("Could not start Ollama.")
            return False
        if not self.model_exists() and not self.pull_model(progress_fn):
            self._log(f"Could not pull model '{self.model}'.")
            return False
        self.available = True
        return True

    def _trim_history(self):
        system = [m for m in self.messages if m["role"] == "system"]
        turns = [m for m in self.messages if m["role"] != "system"]
        if len(turns) > self.MAX_HISTORY:
            turns = turns[-self.MAX_HISTORY:]
        self.messages = system + turns

    def _chat(self, user_content: str, stream_fn: Callable = None) -> str:
        self.messages.append({"role": "user", "content": user_content})
        self._trim_history()
        try:
            r = requests.post(
                f"{self.base_url}/api/chat",
                json={"model": self.model, "messages": self.messages, "stream": True},
                stream=True, timeout=self.chat_timeout,
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
            return ("[AI Timeout] Model took too long to respond. "
                    "Increase 'timeout' in config.json or use a smaller model.")
        except Exception as exc:
            return f"[AI Error] {exc}"

    def analyze_suricata_alerts(self, alerts: List, scanner_params: Dict,
                                stream_fn: Callable = None,
                                memory_summary: str = "") -> str:
        seen: Dict[int, dict] = {}
        for alert in alerts:
            entry = seen.setdefault(alert.signature_id, {
                "signature": alert.signature,
                "category": alert.category,
                "rule_logic": alert.rule_logic,
                "ports": [],
            })
            entry["ports"].append(alert.dst_port)

        prompt = f"IDS DETECTIONS ({len(alerts)} alerts, {len(seen)} unique signatures)\n"
        for sid, info in seen.items():
            ports = sorted(set(info["ports"]))
            ports_str = ", ".join(str(p) for p in ports[:10])
            if len(ports) > 10:
                ports_str += f" ... (+{len(ports) - 10} more)"
            prompt += (
                f"\n[SID {sid}] {info['signature']}\n"
                f"  Category  : {info['category']}\n"
                f"  Ports hit : {ports_str}\n"
                f"  Rule      : {info['rule_logic']}\n"
            )

        if memory_summary:
            prompt += f"\n{memory_summary}\n"

        prompt += (
            f"\nScanner params: {json.dumps(scanner_params)}\n\n"
            "Brief analysis: what triggered these, why, and your top 2 evasion "
            "options. If you recommend changes, include a fenced JSON block."
        )
        return self._chat(prompt, stream_fn=stream_fn)

    def process_user_input(self, user_input: str, scanner_params: Dict) -> str:
        prompt = (
            f'The operator says: "{user_input}"\n\n'
            f"Current scanner parameters:\n{json.dumps(scanner_params, indent=2)}\n\n"
            "Based on the operator's instruction, decide what parameter changes "
            "to make (if any). Output your reasoning, then provide the changes "
            "inside a ```json``` block."
        )
        return self._chat(prompt)

    @staticmethod
    def extract_params(ai_response: str) -> Dict:
        match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", ai_response, re.DOTALL)
        if not match:
            return {}
        try:
            raw = json.loads(match.group(1))
        except (json.JSONDecodeError, AttributeError):
            return {}
        return validate_params(raw)
