"""
main.py — Entry point & orchestrator.

Wires together the Scanner, IDS, AI Controller, and Console UI.
Runs the interactive detect → pause → discuss → adjust → resume loop.

Usage:
    python src/main.py                          # interactive setup
    python src/main.py -t 192.168.1.1           # target only
    python src/main.py -t 127.0.0.1 -f          # fast scan
    python src/main.py -t 10.0.0.1 -s -m gemma3 # stealth + custom model

Flags:
    -t, --target    Target IP address
    -m, --model     Ollama model name  (default: llama3.2)
    -f, --fast      Aggressive scan profile (high rate, low timeout)
    -s, --stealth   Stealthy scan profile (low rate, random ports, jitter)
    -n, --normal    Normal scan profile (default)
    -p, --ports     Port strategy: top | random | sequential | weighted
    -r, --rate      Custom scan rate (probes/sec)
    --timeout       Per-probe timeout in seconds
    -q, --quiet     Suppress per-probe output (only show open ports & alerts)
    -i, --interactive  Force interactive setup wizard
"""

import sys
import os
import json
import time
import argparse
import socket
import logging
from queue import Queue, Empty

try:
    from scapy.all import conf as scapy_conf
except ImportError:
    scapy_conf = None

from scanner import ScannerAgent, PROFILES
from ids import SuricataAgent
from ai_controller import AIController
from ui import ConsoleUI


CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config.json",
)


def load_config() -> dict:
    
    defaults = {
        "ai": {"model": "llama3.2", "base_url": "http://localhost:11434", "timeout": 120},
        "scanner": {"default_profile": "normal", "port_strategy": "top", "scan_rate": None, "timeout": None},
        "ids": {"time_window": 10.0, "detection_threshold": 0.45, "check_interval": 2.5, "cooldown_after_resume": 4.0},
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
            
            for section in defaults:
                if section in user_cfg:
                    defaults[section].update(user_cfg[section])
        except (json.JSONDecodeError, OSError):
            pass  
    return defaults


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="adaptscan",
        description="AI-Controlled Adaptive Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python src/main.py                        Interactive setup\n"
            "  python src/main.py -t 192.168.1.1         Scan a target\n"
            "  python src/main.py -t 127.0.0.1 -f        Fast / aggressive\n"
            "  python src/main.py -t 10.0.0.1 -s -m gemma3\n"
        ),
    )

    
    p.add_argument(
        "-t", "--target",
        help="Target IP address to scan",
    )

    
    profile = p.add_mutually_exclusive_group()
    profile.add_argument(
        "-f", "--fast",
        action="store_const", const="aggressive", dest="profile",
        help="Aggressive scan — high rate, low timeout",
    )
    profile.add_argument(
        "-s", "--stealth",
        action="store_const", const="stealth", dest="profile",
        help="Stealth scan — low rate, random ports, long-tail timing",
    )
    profile.add_argument(
        "-n", "--normal",
        action="store_const", const="normal", dest="profile",
        help="Normal scan (default)",
    )

    
    p.add_argument(
        "-p", "--ports",
        choices=["top", "random", "sequential", "weighted"],
        help="Port selection strategy",
    )
    p.add_argument(
        "-r", "--rate",
        type=float,
        help="Scan rate — probes per second",
    )
    p.add_argument(
        "--timeout",
        type=float,
        help="Per-probe timeout in seconds",
    )

    # ── AI model
    p.add_argument(
        "-m", "--model",
        default=None,
        help="Ollama model name (overrides config.json)",
    )

    
    p.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Only show open ports and IDS alerts",
    )
    p.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Force interactive setup wizard",
    )
    p.add_argument(
        "-I", "--iface",
        help="Network interface to sniff/send on (e.g. eth0)",
    )

    return p


def main():
    ui = ConsoleUI()
    ui.banner()

    
    cfg = load_config()
    cfg_ai = cfg["ai"]
    cfg_scanner = cfg["scanner"]
    cfg_ids = cfg["ids"]

    ui.info(f"Config loaded from [bold]{CONFIG_PATH}[/bold]")

    parser = build_parser()
    args = parser.parse_args()

    
    default_model = cfg_ai.get("model", "llama3.2")
    cli_model = args.model  # None if not passed

    
    need_wizard = args.interactive or args.target is None

    if need_wizard:
        wizard = ui.setup_wizard(
            default_ip=get_local_ip(),
            profiles=list(PROFILES.keys()),
            preset_target=args.target,
            preset_model=cli_model or default_model,
            preset_profile=args.profile or cfg_scanner.get("default_profile"),
            preset_iface=args.iface
        )
        target = wizard["target"]
        model = wizard["model"]
        profile = wizard["profile"]
        iface = wizard.get("iface")
        port_strategy = wizard.get("port_strategy") or cfg_scanner.get("port_strategy")
        rate_override = wizard.get("rate") or cfg_scanner.get("scan_rate")
        timeout_override = wizard.get("timeout") or cfg_scanner.get("timeout")
        quiet = args.quiet
    else:
        target = args.target
        model = cli_model or default_model
        profile = args.profile or cfg_scanner.get("default_profile", "normal")
        iface = args.iface
        port_strategy = args.ports or cfg_scanner.get("port_strategy")
        rate_override = args.rate if args.rate is not None else cfg_scanner.get("scan_rate")
        timeout_override = args.timeout if args.timeout is not None else cfg_scanner.get("timeout")
        quiet = args.quiet

    
    ai = AIController(
        model=model,
        base_url=cfg_ai.get("base_url", "http://localhost:11434"),
        chat_timeout=cfg_ai.get("timeout", 600),
        log_fn=lambda msg: ui.info(msg),
    )

    def _pull_progress(status, completed, total):
        if total > 0:
            pct = (completed / total) * 100
            bar_w = 30
            filled = int(pct / 100 * bar_w)
            bar = "█" * filled + "░" * (bar_w - filled)
            ui.console.print(
                f"\r  [cyan]{status}[/cyan] {bar} {pct:5.1f}%",
                end="", highlight=False,
            )
        else:
            ui.console.print(
                f"\r  [cyan]{status}[/cyan]",
                end="", highlight=False,
            )

    ui.info("Checking Ollama …")
    if not ai.ensure_ready(progress_fn=_pull_progress):
        ui.console.print()
        ui.error("Ollama setup failed.")
        if not ai.is_ollama_installed():
            ui.info(
                "Install Ollama on Kali:  "
                "[bold]curl -fsSL https://ollama.com/install.sh | sh[/bold]"
            )
        return

    ui.console.print()
    ui.info(f"Ollama ready  ·  model: [bold]{model}[/bold]")

    
    if not iface:
        try:
            if scapy_conf:
                
                iface = scapy_conf.route.route(target)[0]
                if not iface:
                    
                    iface = scapy_conf.iface
            
            
            if not iface:
                iface = "eth0"
                
            ui.console.print()
            ui.info(f"Using interface: [bold]{iface}[/bold]")
        except Exception:
            iface = "eth0"

    
    event_queue: Queue = Queue()
    scanner = ScannerAgent(target, event_queue, iface=iface)

    
    scanner.apply_profile(profile)
    if port_strategy:
        scanner.update_params(port_strategy=port_strategy)
    if rate_override is not None:
        scanner.update_params(scan_rate=rate_override)
    if timeout_override is not None:
        scanner.update_params(timeout=timeout_override)

    ids_agent = SuricataAgent(
        target=target,
        iface=iface
    )

    
    DETECTION_THRESHOLD = cfg_ids.get("detection_threshold", 0.45)
    IDS_CHECK_INTERVAL = cfg_ids.get("check_interval", 2.5)
    IDS_COOLDOWN_AFTER_RESUME = cfg_ids.get("cooldown_after_resume", 4.0)

    ui.show_config(target, scanner.params_dict, model, profile)

    
    if need_wizard:
        from rich.prompt import Confirm
        if not Confirm.ask("  [cyan]Start scanning?[/cyan]", default=True):
            return

    ui.info(f"Launching scan against [bold]{target}[/bold] …")
    ui.console.print()
    
    # Start the Wireshark-like background sniffing
    ids_ready = ids_agent.start(use_custom_rules=cfg_ids.get("use_custom_rules", False))

    if not ids_ready and ids_agent._running:
        # Suricata process is alive but didn't emit the ready signal in time
        choice = ui.ids_timeout_prompt()
        if choice == "wait":
            extra_wait = cfg_ids.get("startup_wait_extra", 120)
            ui.info(f"Waiting up to {extra_wait}s more for Suricata …  (Ctrl+C to abort)")
            ids_ready = ids_agent.wait_for_ready(extra_wait)
            if ids_ready:
                ui.info("Suricata IDS ready ✓")
            else:
                ui.warn(
                    f"Suricata still not ready after {extra_wait}s — "
                    "proceeding without IDS confirmation."
                )
        else:
            ui.warn("Skipping IDS wait — scanning without confirmed IDS monitoring.")
    elif not ids_ready:
        ui.warn("Suricata failed to start — scanning without IDS.")
    
    
    scanner.start()

    
    last_ids_check = time.time()
    event_count = 0
    scan_start = time.time()

    try:
        while True:
            if not scanner._running and event_queue.empty():
                break

            
            batch = []
            while True:
                try:
                    batch.append(event_queue.get_nowait())
                except Empty:
                    break

            for ev in batch:
                event_count += 1

                if quiet:
                    if ev.result == "open":
                        ui.scan_event(ev)
                else:
                    
                    if ev.result == "open" or event_count % 2 == 0:
                        ui.scan_event(ev)

            if batch and event_count % 8 == 0 and not quiet:
                ui.ids_status(ids_agent.stats)

            
            now = time.time()
            if now - last_ids_check >= IDS_CHECK_INTERVAL:
                last_ids_check = now
                alerts = ids_agent.get_new_alerts()

                if alerts:
                    scanner.pause()
                    time.sleep(0.5)  

                    
                    while not event_queue.empty():
                        try:
                            event_queue.get_nowait()
                        except Empty:
                            break

                    ui.suricata_alert(alerts)

                    ui.info("AI is analysing the detection …")
                    ui.console.print()
                    ui.console.print("  [bold blue]🤖 AI Analyst[/bold blue]  ", end="")

                    # Stream tokens to terminal as they arrive — no silent wait
                    stream_buf = []
                    def _stream(token):
                        stream_buf.append(token)
                        ui.console.print(token, end="", highlight=False)

                    analysis = ai.analyze_suricata_alerts(
                        alerts, scanner.params_dict, stream_fn=_stream
                    )
                    ui.console.print()  # newline after streamed output

                    
                    while True:
                        user_input = ui.user_prompt()
                        cmd = user_input.lower().strip()

                        if cmd in ("quit", "exit", "stop", "q"):
                            scanner.stop()
                            ui.info("Scan terminated by operator.")
                            return

                        if cmd in ("resume", "continue", "go", "r", "c", ""):
                            break

                        ui.info("AI is processing …")
                        response = ai.process_user_input(
                            user_input, scanner.params_dict
                        )
                        ui.ai_message(response)

                        new_params = ai.extract_params(response)
                        if new_params:
                            scanner.update_params(**new_params)
                            ui.param_change(new_params)

                    ui.resuming()
                    ids_agent.alerts.clear()
                    scanner.resume()
                    last_ids_check = time.time() + IDS_COOLDOWN_AFTER_RESUME
                    event_count = 0

            if not batch:
                time.sleep(0.05)

    except KeyboardInterrupt:
        ui.console.print()
        ui.info("Interrupted (Ctrl+C)")
    finally:
        scanner.stop()
        ids_agent.stop()
        elapsed = time.time() - scan_start
        ui.scan_complete({
            "Duration": f"{elapsed:.1f}s",
            "Total probes": scanner.scan_count,
            "IDS alerts": len(ids_agent.alerts),
            "Target": target,
        }, open_ports=scanner.open_ports)


if __name__ == "__main__":
    main()