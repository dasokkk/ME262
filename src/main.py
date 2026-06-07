"""
main.py — Entry point & orchestrator.

Wires together the Scanner, IDS, AI Controller, adaptive controller, evasion
memory, and console UI. Expands the target spec, then for each target runs the
detect -> pause -> analyse/adapt -> resume loop.

Usage:
    python src/main.py                              interactive setup
    python src/main.py -t 192.168.1.1               scan a target
    python src/main.py -t 10.0.0.0/24 -s            scan a CIDR, stealthily
    python src/main.py -t host -f --auto-evade      fast scan, auto-adapt on detection
    python src/main.py -t host --export run1        write run1.json / run1.csv
"""

import os
import sys
import json
import time
import socket
import argparse
from queue import Queue, Empty

from rich.prompt import Confirm

try:
    from scapy.all import conf as scapy_conf
except ImportError:
    scapy_conf = None

from scanner import ScannerAgent, PROFILES
from ids import make_ids
from ai_controller import AIController
from ui import ConsoleUI
from targets import expand_targets, is_single_host
from controller import RateTracker, AdaptiveController
from evasion_memory import EvasionMemory
from reporter import SessionReporter

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(PROJECT_ROOT, "config.json")
MEMORY_PATH = os.path.join(PROJECT_ROOT, "evasion_memory.json")


def load_config() -> dict:
    defaults = {
        "ai": {"model": "llama3.2", "base_url": "http://localhost:11434", "timeout": 120},
        "scanner": {"default_profile": "normal", "port_strategy": "top", "scan_rate": None, "timeout": None},
        "ids": {
            "engine": "suricata", "time_window": 10.0, "detection_threshold": 0.45,
            "check_interval": 2.5, "cooldown_after_resume": 4.0, "use_custom_rules": False,
            "startup_wait_extra": 120,
        },
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
        prog="me262",
        description="AI-Controlled Adaptive Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python src/main.py                          Interactive setup\n"
            "  python src/main.py -t 192.168.1.1           Scan a target\n"
            "  python src/main.py -t 10.0.0.0/24 -s        Scan a CIDR, stealthily\n"
            "  python src/main.py -t host -f --auto-evade  Auto-adapt on detection\n"
        ),
    )

    p.add_argument("-t", "--target", help="Target IP, hostname, CIDR range, or comma-separated list")

    profile = p.add_mutually_exclusive_group()
    profile.add_argument("-f", "--fast", action="store_const", const="aggressive", dest="profile",
                         help="Aggressive scan — high rate, low timeout")
    profile.add_argument("-s", "--stealth", action="store_const", const="stealth", dest="profile",
                         help="Stealth scan — low rate, random ports, long-tail timing")
    profile.add_argument("-n", "--normal", action="store_const", const="normal", dest="profile",
                         help="Normal scan (default)")

    p.add_argument("-p", "--ports", choices=["top", "random", "sequential", "weighted"],
                   help="Port selection strategy")
    p.add_argument("-r", "--rate", type=float, help="Scan rate — probes per second")
    p.add_argument("--timeout", type=float, help="Per-probe timeout in seconds")
    p.add_argument("-m", "--model", default=None, help="Ollama model name (overrides config.json)")
    p.add_argument("-q", "--quiet", action="store_true", help="Only show open ports and IDS alerts")
    p.add_argument("-g", type=int, dest="source_port", help="Use given source port number")

    p.add_argument("--disable-ai", action="store_true",
                   help="Disable AI analysis (auto-enabled if model is 'noai')")
    p.add_argument("--disable-ids", action="store_true", help="Disable IDS monitoring")
    p.add_argument("--ids-engine", choices=["suricata", "snort", "zeek"],
                   help="IDS backend to run (overrides config.json)")
    p.add_argument("--auto-evade", action="store_true",
                   help="Automatically walk the evasion ladder on each detection (no prompts)")

    p.add_argument("--spoof-app", action="store_true",
                   help="[EVASION] Spoof app-layer payloads (HTTP GET / TLS Hello / DNS)")
    p.add_argument("--full-connect", action="store_true",
                   help="[EVASION] Complete the 3-way TCP handshake (connect scan)")
    p.add_argument("--ssl-scan", action="store_true",
                   help="[EVASION] Perform real SSL/TLS handshakes on open ports")
    p.add_argument("--proxy", help="[EVASION] Route scans through proxies (comma-separated)")
    p.add_argument("--mtu", type=int, help="[EVASION] Fragment packets to MTU (multiple of 8)")
    p.add_argument("-D", "--decoys", help="[EVASION] Decoy source IPs (use RND for random, ME for self)")
    p.add_argument("-S", "--spoof-ip", help="[EVASION] Spoof the source IP address")
    p.add_argument("--spoof-mac", help="[EVASION] Spoof the source MAC address")
    p.add_argument("--ttl", type=int, help="[EVASION] Fixed IP TTL (1-255)")
    p.add_argument("--ip-options", help="[EVASION] IP options as a hex string (e.g. \\x01\\x07)")
    p.add_argument("--badsum", action="store_true", help="[EVASION] Send a deliberately bad TCP checksum")

    p.add_argument("--banner-grab", action="store_true", help="Grab banners/versions on open ports")
    p.add_argument("--export", help="Write JSON+CSV reports to PREFIX.json / PREFIX.csv")
    p.add_argument("-i", "--interactive", action="store_true", help="Force interactive setup wizard")
    p.add_argument("-I", "--iface", help="Network interface to sniff/send on (e.g. eth0)")
    return p


def _ai_interaction(ui, ai, scanner, alerts, memory, reporter) -> str:
    """Run the AI analysis + operator chat loop. Returns 'continue' or 'quit'."""
    ui.info("AI is analysing the detection ...")
    ui.console.print()
    ui.console.print("  [bold blue]AI Analyst[/bold blue]  ", end="")

    def _stream(token):
        ui.console.print(token, end="", highlight=False)

    ai.analyze_suricata_alerts(
        alerts, scanner.params_dict, stream_fn=_stream,
        memory_summary=memory.summary_for_prompt(),
    )
    ui.console.print()

    while True:
        user_input = ui.user_prompt()
        cmd = user_input.lower().strip()
        if cmd in ("quit", "exit", "stop", "q"):
            ui.info("Scan terminated by operator.")
            return "quit"
        if cmd in ("resume", "continue", "go", "r", "c", ""):
            return "continue"
        ui.info("AI is processing ...")
        response = ai.process_user_input(user_input, scanner.params_dict)
        ui.ai_message(response)
        new_params = ai.extract_params(response)
        if new_params:
            scanner.update_params(**new_params)
            reporter.record_param_change(new_params, source="ai")
            ui.param_change(new_params)


def _apply_adaptive_step(ui, scanner, controller, reporter, rate) -> bool:
    step = controller.next_step(scanner.params_dict)
    if step is None:
        ui.adaptive_exhausted()
        return False
    description, changes = step
    scanner.update_params(**changes)
    reporter.record_param_change(changes, source="auto-evade")
    ui.adaptive_change(description, changes, rate)
    return True


def _finalize_target(ui, target_ip, display, scanner, reporter, memory, detected_sids):
    reporter.total_probes += scanner.scan_count
    service_info = scanner.service_info
    for port in scanner.open_ports:
        reporter.record_open(target_ip, port, service_info.get(port, ""))
    memory.record(scanner.params_dict, list(detected_sids),
                  detected=bool(detected_sids), target=target_ip)
    ui.scan_complete(
        {"Target": display, "Probes": scanner.scan_count,
         "Open ports": len(scanner.open_ports), "Detections": len(detected_sids)},
        open_ports=scanner.open_ports, banners=service_info,
    )


def _build_overrides(settings) -> dict:
    overrides = {}
    if settings["port_strategy"]:
        overrides["port_strategy"] = settings["port_strategy"]
    if settings["rate_override"] is not None:
        overrides["scan_rate"] = settings["rate_override"]
    if settings["timeout_override"] is not None:
        overrides["timeout"] = settings["timeout_override"]
    if settings["source_port"] is not None:
        overrides["source_port"] = settings["source_port"]
    for key, value in settings["evasion"].items():
        if value not in (None, False, [], ""):
            overrides[key] = value
    return overrides


def scan_target(target_ip, display, ui, ai, ids_agent, memory, reporter, settings) -> str:
    """Run the full scan/IDS/adapt loop for one target. Returns 'done' or 'quit'."""
    event_queue: Queue = Queue()
    scanner = ScannerAgent(display, event_queue, iface=settings["iface"], target_ip=target_ip)
    scanner.apply_profile(settings["profile"])
    scanner.update_params(**_build_overrides(settings))

    ui.show_config(target_ip, scanner.params_dict, settings["model"], settings["profile"])
    ui.info(f"Launching scan against [bold]{display}[/bold] ...")
    ui.console.print()

    try:
        scanner.start()
    except RuntimeError as exc:
        ui.error(str(exc))
        return "quit"

    if ids_agent and not settings["disable_ids"]:
        ids_agent.get_new_alerts()

    disable_ai = settings["disable_ai"]
    disable_ids = settings["disable_ids"]
    auto_evade = settings["auto_evade"]
    quiet = settings["quiet"]
    threshold = settings["detection_threshold"]
    check_interval = settings["check_interval"]
    cooldown = settings["cooldown"]

    tracker = RateTracker(window=settings["time_window"])
    controller = AdaptiveController(proxy=settings["evasion"].get("proxy"))
    detected_sids = set()
    last_ids_check = time.time()
    event_count = 0

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
                if ev.result == "sent":
                    tracker.record_probe()
                if ev.result in ("open", "banner"):
                    reporter.record_open(target_ip, ev.dst_port, ev.banner)
                if quiet:
                    if ev.result in ("open", "banner"):
                        ui.scan_event(ev)
                elif ev.result in ("open", "banner") or event_count % 2 == 0:
                    ui.scan_event(ev)

            if batch and event_count % 8 == 0 and not quiet and not disable_ids:
                ui.ids_status(ids_agent.stats)

            now = time.time()
            if not disable_ids and now - last_ids_check >= check_interval:
                last_ids_check = now
                alerts = ids_agent.get_new_alerts()
                if alerts:
                    tracker.record_alert(len(alerts))
                    scanner.pause()
                    time.sleep(0.5)
                    while not event_queue.empty():
                        try:
                            event_queue.get_nowait()
                        except Empty:
                            break

                    for alert in alerts:
                        reporter.record_alert(alert)
                        detected_sids.add(alert.signature_id)
                    ui.suricata_alert(alerts)
                    rate = tracker.rate()

                    if auto_evade:
                        _apply_adaptive_step(ui, scanner, controller, reporter, rate)
                    elif not disable_ai:
                        if _ai_interaction(ui, ai, scanner, alerts, memory, reporter) == "quit":
                            scanner.stop()
                            _finalize_target(ui, target_ip, display, scanner, reporter, memory, detected_sids)
                            return "quit"
                    else:
                        if rate >= threshold and not controller.exhausted():
                            _apply_adaptive_step(ui, scanner, controller, reporter, rate)
                        else:
                            ui.console.print("\n  [bold red]IDS ALERT! AI disabled.[/bold red]")
                            if not Confirm.ask("  [cyan]Continue scanning?[/cyan]", default=True):
                                scanner.stop()
                                _finalize_target(ui, target_ip, display, scanner, reporter, memory, detected_sids)
                                return "quit"

                    ui.resuming()
                    ids_agent.get_new_alerts()
                    scanner.resume()
                    last_ids_check = time.time() + cooldown
                    event_count = 0

            if not batch:
                time.sleep(0.05)
    except KeyboardInterrupt:
        ui.console.print()
        ui.info("Interrupted (Ctrl+C)")
        scanner.stop()
        _finalize_target(ui, target_ip, display, scanner, reporter, memory, detected_sids)
        return "quit"

    scanner.stop()
    _finalize_target(ui, target_ip, display, scanner, reporter, memory, detected_sids)
    return "done"


def _gather_settings(args, cfg, ui):
    """Resolve all run settings from the wizard or CLI flags."""
    cfg_ai, cfg_scanner, cfg_ids = cfg["ai"], cfg["scanner"], cfg["ids"]
    default_model = cfg_ai.get("model", "llama3.2")
    need_wizard = args.interactive or args.target is None

    if need_wizard:
        wiz = ui.setup_wizard(
            default_ip=get_local_ip(),
            profiles=list(PROFILES.keys()),
            preset_target=args.target,
            preset_model=args.model or default_model,
            preset_profile=args.profile or cfg_scanner.get("default_profile"),
            preset_iface=args.iface,
        )
        target_spec = wiz["target"]
        model = wiz["model"]
        profile = wiz["profile"]
        port_strategy = wiz.get("port_strategy") or cfg_scanner.get("port_strategy")
        rate_override = wiz.get("rate") or cfg_scanner.get("scan_rate")
        timeout_override = wiz.get("timeout") or cfg_scanner.get("timeout")
        evasion = {k: wiz.get(k) for k in (
            "spoof_app", "full_connect", "ssl_scan", "badsum", "proxy", "decoys",
            "spoof_ip", "spoof_mac", "ttl", "ip_options", "mtu", "banner_grab",
        )}
        ids_engine = wiz.get("ids_engine", "suricata")
        disable_ids = wiz.get("disable_ids", False)
        auto_evade = wiz.get("auto_evade", False)
    else:
        target_spec = args.target
        model = args.model or default_model
        profile = args.profile or cfg_scanner.get("default_profile", "normal")
        port_strategy = args.ports or cfg_scanner.get("port_strategy")
        rate_override = args.rate if args.rate is not None else cfg_scanner.get("scan_rate")
        timeout_override = args.timeout if args.timeout is not None else cfg_scanner.get("timeout")
        evasion = {
            "spoof_app": args.spoof_app, "full_connect": args.full_connect,
            "ssl_scan": args.ssl_scan, "badsum": args.badsum, "proxy": args.proxy,
            "decoys": [d.strip() for d in args.decoys.split(",") if d.strip()] if args.decoys else [],
            "spoof_ip": args.spoof_ip, "spoof_mac": args.spoof_mac, "ttl": args.ttl,
            "ip_options": args.ip_options, "mtu": args.mtu, "banner_grab": args.banner_grab,
        }
        ids_engine = args.ids_engine or cfg_ids.get("engine", "suricata")
        disable_ids = args.disable_ids
        auto_evade = args.auto_evade

    disable_ai = args.disable_ai or model.lower() == "noai"
    settings = {
        "target_spec": target_spec, "model": model, "profile": profile,
        "port_strategy": port_strategy, "rate_override": rate_override,
        "timeout_override": timeout_override, "source_port": args.source_port,
        "evasion": evasion, "quiet": args.quiet, "disable_ai": disable_ai,
        "disable_ids": disable_ids, "auto_evade": auto_evade, "ids_engine": ids_engine,
        "iface": args.iface,
        "time_window": cfg_ids.get("time_window", 10.0),
        "detection_threshold": cfg_ids.get("detection_threshold", 0.45),
        "check_interval": cfg_ids.get("check_interval", 2.5),
        "cooldown": cfg_ids.get("cooldown_after_resume", 4.0),
    }
    return settings, need_wizard


def _setup_ai(settings, cfg_ai, ui):
    ai = AIController(
        model=settings["model"],
        base_url=cfg_ai.get("base_url", "http://localhost:11434"),
        chat_timeout=cfg_ai.get("timeout", 600),
        log_fn=lambda msg: ui.info(msg),
    )

    def _pull_progress(status, completed, total):
        if total > 0:
            pct = completed / total * 100
            bar = "█" * int(pct / 100 * 30) + "░" * (30 - int(pct / 100 * 30))
            ui.console.print(f"\r  [cyan]{status}[/cyan] {bar} {pct:5.1f}%", end="", highlight=False)
        else:
            ui.console.print(f"\r  [cyan]{status}[/cyan]", end="", highlight=False)

    ui.info("Checking Ollama ...")
    if not ai.ensure_ready(progress_fn=_pull_progress):
        ui.console.print()
        ui.error("Ollama setup failed.")
        if not ai.is_ollama_installed():
            ui.info("Install Ollama:  [bold]curl -fsSL https://ollama.com/install.sh | sh[/bold]")
        return None
    ui.console.print()
    ui.info(f"Ollama ready  ·  model: [bold]{settings['model']}[/bold]")
    return ai


def _detect_iface(iface, target_ip, ui):
    if iface:
        return iface
    try:
        if scapy_conf:
            iface = scapy_conf.route.route(target_ip)[0] or scapy_conf.iface
    except Exception:
        iface = None
    iface = iface or "eth0"
    ui.console.print()
    ui.info(f"Using interface: [bold]{iface}[/bold]")
    return iface


def _start_ids(ids_agent, cfg_ids, ui):
    ready = ids_agent.start(use_custom_rules=cfg_ids.get("use_custom_rules", False))
    if not ready and ids_agent._running:
        if ui.ids_timeout_prompt() == "wait":
            extra = cfg_ids.get("startup_wait_extra", 120)
            ui.info(f"Waiting up to {extra}s more for the IDS ...  (Ctrl+C to abort)")
            if ids_agent.wait_for_ready(extra):
                ui.info("IDS ready.")
            else:
                ui.warn(f"IDS still not ready after {extra}s — proceeding without confirmation.")
        else:
            ui.warn("Skipping IDS wait — scanning without confirmed IDS monitoring.")
    elif not ready:
        ui.warn("IDS failed to start — scanning without IDS.")


def main():
    ui = ConsoleUI()
    ui.banner()

    cfg = load_config()
    ui.info(f"Config loaded from [bold]{CONFIG_PATH}[/bold]")

    args = build_parser().parse_args()
    settings, need_wizard = _gather_settings(args, cfg, ui)

    if settings["evasion"]["mtu"] and settings["evasion"]["mtu"] % 8 != 0:
        ui.error("MTU must be a multiple of 8.")
        sys.exit(1)

    ai = None
    if not settings["disable_ai"]:
        ai = _setup_ai(settings, cfg["ai"], ui)
        if ai is None:
            return

    targets = expand_targets(settings["target_spec"])
    if not targets:
        ui.error(f"No valid targets resolved from '{settings['target_spec']}'.")
        return
    display_single = settings["target_spec"] if is_single_host(settings["target_spec"]) else None

    settings["iface"] = _detect_iface(settings["iface"], targets[0], ui)

    ids_agent = None
    if not settings["disable_ids"]:
        ids_agent = make_ids(settings["ids_engine"], targets[0], settings["iface"], cfg["ids"])

    reporter = SessionReporter(targets)
    memory = EvasionMemory(MEMORY_PATH)

    if need_wizard and not Confirm.ask("  [cyan]Start scanning?[/cyan]", default=True):
        return

    if ids_agent:
        ui.info("Starting IDS ...")
        _start_ids(ids_agent, cfg["ids"], ui)

    try:
        for idx, target_ip in enumerate(targets, 1):
            display = display_single if (display_single and len(targets) == 1) else target_ip
            ui.target_header(display, idx, len(targets))
            if scan_target(target_ip, display, ui, ai, ids_agent, memory, reporter, settings) == "quit":
                break
    finally:
        if ids_agent:
            ids_agent.stop()
        ui.session_summary(reporter.after_action())
        if args.export:
            json_path = f"{args.export}.json"
            csv_path = f"{args.export}.csv"
            reporter.export_json(json_path)
            reporter.export_csv(csv_path)
            ui.export_done([json_path, csv_path])


if __name__ == "__main__":
    main()
