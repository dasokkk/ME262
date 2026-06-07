"""
Console UI — Rich-powered terminal interface.

Provides styled banners, an interactive setup wizard, live scan output, IDS
alerts, AI analyst panels, adaptive-evasion notices, and the final reports.
"""

import time
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.prompt import Prompt, Confirm
from rich import box
from rich.text import Text

from reporter import SERVICES


class ConsoleUI:

    def __init__(self):
        self.console = Console()

    def banner(self):
        art = Text()
        lines = [
            "",
            "    ╔══════════════════════════════════════════════════════════╗",
            "    ║                                                          ║",
            "    ║      █▀▄▀█ █▀▀ ▀▀█ █▀▀ ▀▀█                               ║",
            "    ║      █ ▀ █ █▀▀ █▀▀ █▀█ █▀▀                               ║",
            "    ║      ▀   ▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀▀▀                               ║",
            "    ║                                                          ║",
            "    ╠══════════════════════════════════════════════════════════╣",
            "    ║            AI-Controlled Adaptive Stealth Scanner        ║",
            "    ║                   github.com/dasokkk                     ║",
            "    ╚══════════════════════════════════════════════════════════╝",
            "       For advanced options, use --help",
            "",
        ]
        for line in lines:
            art.append(line + "\n")
        self.console.print(art, style="bold cyan", highlight=False)

    def setup_wizard(
        self,
        default_ip: str,
        profiles: List[str],
        preset_target: Optional[str] = None,
        preset_model: Optional[str] = None,
        preset_profile: Optional[str] = None,
        preset_iface: Optional[str] = None,
    ) -> Dict:
        self.console.print(Rule("[bold yellow]  Setup Wizard[/bold yellow]", style="yellow"))
        self.console.print()

        self.console.print("  [bold]1.[/bold] [cyan]Target Host, IP, CIDR, or list[/cyan]")
        self.console.print("     [dim]e.g. domain.com, 10.0.0.5, 192.168.1.0/24, or a comma list.[/dim]")
        target = Prompt.ask("     [cyan]Target[/cyan]", default=preset_target or "example.com")
        self.console.print()

        self.console.print("  [bold]2.[/bold] [cyan]Scan profile[/cyan]")
        profile_info = {
            "aggressive": ("Aggressive", "High rate (20/s), low timeout, fixed timing — fast & loud"),
            "normal": ("Normal", "Moderate rate (3/s), jitter timing — balanced"),
            "stealth": ("Stealth", "Low rate (0.5/s), random ports, long-tail delays — quiet"),
        }
        for i, prof in enumerate(profiles, 1):
            name, desc = profile_info.get(prof, (prof, ""))
            marker = "[bold green]>[/bold green]" if prof == "normal" else " "
            self.console.print(f"     {marker} [bold]{i}.[/bold] {name}")
            self.console.print(f"        [dim]{desc}[/dim]")
        profile_map = {str(i): p for i, p in enumerate(profiles, 1)}
        profile_map.update({p: p for p in profiles})
        raw = Prompt.ask("     [cyan]Choose profile[/cyan] [dim](1/2/3 or name)[/dim]",
                         default=preset_profile or "normal")
        profile = profile_map.get(raw.lower().strip(), raw.lower().strip())
        if profile not in profiles:
            self.warn(f"Unknown profile '{profile}', defaulting to 'normal'")
            profile = "normal"
        self.console.print()

        self.console.print("  [bold]3.[/bold] [cyan]Port strategy[/cyan]")
        strategies = {
            "top": "Well-known ports (22, 80, 443, 3389 ...)",
            "random": "50 random ports from full range",
            "sequential": "Ports 1–1024 in order",
            "weighted": "Top ports + random high ports",
        }
        for key, desc in strategies.items():
            self.console.print(f"       [bold]{key:<12}[/bold] [dim]{desc}[/dim]")
        port_strategy = Prompt.ask("     [cyan]Strategy[/cyan]", default="top",
                                   choices=list(strategies.keys()))
        self.console.print()

        rate = self._ask_optional_float("4.", "Scan rate", "probes per second")
        timeout = self._ask_optional_float("5.", "Probe timeout", "seconds")

        self.console.print("  [bold]6.[/bold] [cyan]Ollama AI model[/cyan]")
        self.console.print("     [dim]LLM for the AI analyst. Type 'noai' to disable AI analysis.[/dim]")
        model = Prompt.ask("     [cyan]Model[/cyan]", default=preset_model or "llama3.2")
        self.console.print()

        self.console.print("  [bold]7.[/bold] [cyan]Advanced Evasion Features[/cyan] [dim](Optional)[/dim]")
        spoof_app = Confirm.ask("     [cyan]Spoof Application Layer (HTTP/TLS/DNS)[/cyan]", default=False)
        full_connect = Confirm.ask("     [cyan]Full TCP Handshake (Connect Scan)[/cyan]", default=False)
        ssl_scan = Confirm.ask("     [cyan]Encrypted Scanning (SSL/TLS)[/cyan]", default=False)
        badsum = Confirm.ask("     [cyan]Bad TCP Checksum[/cyan]", default=False)
        proxy_raw = Prompt.ask("     [cyan]Proxy Route (e.g. socks5://127.0.0.1:9050)[/cyan]", default="")
        proxy = proxy_raw.strip() or None
        decoys_raw = Prompt.ask("     [cyan]Decoys (e.g. RND,RND,ME or 10.0.0.5,ME)[/cyan]", default="")
        decoys = [d.strip() for d in decoys_raw.split(",") if d.strip()]
        spoof_ip_raw = Prompt.ask("     [cyan]Spoof Source IP[/cyan]", default="")
        spoof_ip = spoof_ip_raw.strip() or None
        spoof_mac_raw = Prompt.ask("     [cyan]Spoof Source MAC[/cyan]", default="")
        spoof_mac = spoof_mac_raw.strip() or None
        ttl = self._ask_optional_int("     ", "Custom TTL (1-255)")
        ip_options_raw = Prompt.ask("     [cyan]IP Options (hex, e.g. \\x01\\x07)[/cyan]", default="")
        ip_options = ip_options_raw.strip() or None
        mtu = self._ask_optional_int("     ", "IP Fragmentation MTU (e.g. 8, 16)")
        banner_grab = Confirm.ask("     [cyan]Banner / version grab on open ports[/cyan]", default=False)
        self.console.print()

        self.console.print("  [bold]8.[/bold] [cyan]Detection & Adaptation[/cyan]")
        ids_engine = Prompt.ask("     [cyan]IDS engine[/cyan]", default="suricata",
                                choices=["suricata", "snort", "zeek"])
        disable_ids = Confirm.ask("     [cyan]Disable IDS Monitoring?[/cyan]", default=False)
        auto_evade = Confirm.ask("     [cyan]Auto-evade (adapt automatically on detection)[/cyan]", default=False)
        self.console.print()

        self._print_summary(target, profile, port_strategy, rate, timeout, model, ids_engine)
        return {
            "target": target, "model": model, "profile": profile,
            "port_strategy": port_strategy, "rate": rate, "timeout": timeout,
            "spoof_app": spoof_app, "full_connect": full_connect, "ssl_scan": ssl_scan,
            "badsum": badsum, "proxy": proxy, "decoys": decoys, "spoof_ip": spoof_ip,
            "spoof_mac": spoof_mac, "ttl": ttl, "ip_options": ip_options, "mtu": mtu,
            "banner_grab": banner_grab, "ids_engine": ids_engine,
            "disable_ids": disable_ids, "auto_evade": auto_evade,
        }

    def _ask_optional_float(self, num: str, label: str, unit: str) -> Optional[float]:
        self.console.print(f"  [bold]{num}[/bold] [cyan]{label}[/cyan] [dim]({unit})[/dim]")
        self.console.print("     [dim]Press Enter to use the profile default.[/dim]")
        raw = Prompt.ask(f"     [cyan]{label}[/cyan]", default="")
        self.console.print()
        if not raw.strip():
            return None
        try:
            return float(raw)
        except ValueError:
            self.warn("Invalid number, using profile default.")
            return None

    def _ask_optional_int(self, indent: str, label: str) -> Optional[int]:
        raw = Prompt.ask(f"{indent}[cyan]{label}[/cyan]", default="")
        if not raw.strip():
            return None
        try:
            return int(raw)
        except ValueError:
            self.warn(f"Invalid value for {label}, ignoring.")
            return None

    def _print_summary(self, target, profile, port_strategy, rate, timeout, model, ids_engine):
        self.console.print(Rule("[bold yellow]  Configuration Summary[/bold yellow]", style="yellow"))
        self.console.print()
        summary = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
        summary.add_column("Key", style="cyan", min_width=16)
        summary.add_column("Value", style="bold white")
        summary.add_row("Target", target)
        summary.add_row("Profile", profile)
        summary.add_row("Port Strategy", port_strategy)
        summary.add_row("Scan Rate", f"{rate} /s" if rate else "(profile default)")
        summary.add_row("Timeout", f"{timeout}s" if timeout else "(profile default)")
        summary.add_row("AI Model", model)
        summary.add_row("IDS Engine", ids_engine)
        self.console.print(summary)
        self.console.print()

    def show_config(self, target: str, params: Dict, model: str, profile: str = "custom"):
        table = Table(title="Active Configuration", box=box.ROUNDED,
                      title_style="bold white", border_style="cyan")
        table.add_column("Parameter", style="cyan", min_width=16)
        table.add_column("Value", style="green")
        table.add_row("Target", target)
        table.add_row("Profile", profile)
        for k, v in params.items():
            table.add_row(k.replace("_", " ").title(), str(v))
        table.add_row("AI Model", model)
        self.console.print(table)
        self.console.print()

    def target_header(self, target: str, index: int, total: int):
        if total > 1:
            self.console.print(Rule(f"[bold magenta]  Target {index}/{total}: {target}  [/bold magenta]",
                                    style="magenta"))
            self.console.print()

    def scan_event(self, event):
        port_str = f"{event.dst_port}/tcp"
        ts = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
        styles = {
            "open": ("[+]", "bold green"),
            "closed": ("[-]", "dim"),
            "filtered": ("[~]", "yellow"),
            "sent": ("[>]", "dim"),
            "banner": ("[*]", "cyan"),
        }
        icon, style = styles.get(event.result, ("[!]", "red"))
        suffix = f"  {event.banner}" if event.banner else ""
        self.console.print(
            f"  {icon} [{ts}]  {port_str:<12} {event.result:<10} "
            f"{event.duration_ms:>7.1f}ms  {event.scan_type}{suffix}",
            style=style, highlight=False,
        )

    def ids_status(self, stats: Dict):
        parts = [f"[cyan]{k}[/cyan]={v}" for k, v in stats.items()]
        self.console.print(f"  [dim]IDS | {' | '.join(parts)}[/dim]", highlight=False)

    def ids_timeout_prompt(self) -> str:
        self.console.print()
        self.console.print(Rule("[bold yellow]  IDS Not Ready[/bold yellow]", style="yellow"))
        self.console.print()
        self.console.print("  [yellow][!][/yellow]  The IDS did not confirm readiness within the timeout.\n")
        self.console.print("     [bold]1.[/bold] [cyan]Wait[/cyan]     — Keep waiting for the IDS to finish loading")
        self.console.print("     [bold]2.[/bold] [cyan]Skip IDS[/cyan] — Start scanning immediately without IDS monitoring")
        self.console.print()
        choice = Prompt.ask("     [cyan]Choice[/cyan]", choices=["1", "2"], default="1")
        self.console.print()
        return "wait" if choice == "1" else "skip"

    def suricata_alert(self, alerts: List):
        self.console.print()
        self.console.print(Rule(
            f"[bold red]  IDS ALERT ({len(alerts)}) — SCAN PAUSED  [/bold red]", style="red"))
        self.console.print()
        table = Table(title="Real-Time Signatures Triggered", box=box.SIMPLE_HEAVY, border_style="yellow")
        table.add_column("Sig ID", style="cyan")
        table.add_column("Signature Name", style="white")
        table.add_column("Category", style="yellow")
        table.add_column("Dest Port", style="red", justify="right")
        for alert in alerts:
            table.add_row(str(alert.signature_id), alert.signature, alert.category, str(alert.dst_port))
        self.console.print(table)
        if alerts and alerts[0].rule_logic != "Rule logic unavailable.":
            self.console.print()
            self.console.print("  [bold]Extracted Rule Logic (Reason for detection):[/bold]")
            self.console.print(f"  [yellow]{alerts[0].rule_logic}[/yellow]")
        self.console.print()

    def ai_message(self, message: str):
        self.console.print()
        self.console.print(Panel(message, title="AI Analyst", border_style="blue", padding=(1, 2)))

    def user_prompt(self) -> str:
        self.console.print()
        return Prompt.ask(
            "[bold cyan] What should we do now?[/bold cyan]  "
            "[dim](type 'resume' to continue, 'quit' to stop)[/dim]")

    def param_change(self, params: Dict):
        if not params:
            return
        self.console.print()
        self.console.print("  [bold green][+] Parameter adjustments applied:[/bold green]")
        for k, v in params.items():
            self.console.print(f"    [green]-[/green] {k} -> {v}")

    def adaptive_change(self, description: str, params: Dict, detection_rate: float):
        self.console.print()
        self.console.print(
            f"  [bold magenta]Auto-evade[/bold magenta] "
            f"[dim](detection rate {detection_rate*100:.0f}%)[/dim]: {description}")
        for k, v in params.items():
            self.console.print(f"    [magenta]-[/magenta] {k} -> {v}")
        self.console.print()

    def adaptive_exhausted(self):
        self.console.print()
        self.console.print("  [yellow][!] Evasion ladder exhausted — no further automatic adjustments.[/yellow]")
        self.console.print()

    def resuming(self):
        self.console.print()
        self.console.print(Rule("[bold green]SCAN RESUMING[/bold green]", style="green"))
        self.console.print()

    def scan_complete(self, stats: Dict, open_ports: List[int] = None,
                      banners: Dict[int, str] = None):
        banners = banners or {}
        self.console.print()
        self.console.print(Rule("[bold cyan]SCAN COMPLETE[/bold cyan]", style="cyan"))
        self.console.print()
        if open_ports:
            self.console.print("  [bold white]PORT      STATE  SERVICE        VERSION[/bold white]")
            for port in sorted(set(open_ports)):
                svc = SERVICES.get(port, "unknown")
                version = banners.get(port, "")
                self.console.print(
                    f"  [cyan]{port}/tcp[/cyan]".ljust(18)
                    + f" [bold green]open[/bold green]   {svc:<14} [dim]{version}[/dim]")
            self.console.print()
        if stats:
            table = Table(box=box.ROUNDED, border_style="cyan")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="white")
            for k, v in stats.items():
                table.add_row(str(k), str(v))
            self.console.print(table)
        self.console.print()

    def session_summary(self, debrief: Dict):
        self.console.print(Rule("[bold cyan]  Session Debrief  [/bold cyan]", style="cyan"))
        self.console.print()
        table = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
        table.add_column("Metric", style="cyan", min_width=20)
        table.add_column("Value", style="white")
        table.add_row("Targets scanned", str(debrief["targets"]))
        table.add_row("Total probes", str(debrief["total_probes"]))
        table.add_row("Total IDS alerts", str(debrief["total_alerts"]))
        sigs = ", ".join(str(s) for s in debrief["unique_signatures"]) or "none"
        table.add_row("Unique signatures", sigs)
        table.add_row("Adaptations applied", str(debrief["adaptations"]))
        self.console.print(table)
        self.console.print()
        for target, ports in debrief["open_ports"].items():
            ports_str = ", ".join(str(p) for p in ports) or "none"
            self.console.print(f"  [cyan]{target}[/cyan]: [green]{ports_str}[/green]")
        self.console.print()

    def export_done(self, paths: List[str]):
        for path in paths:
            self.console.print(f"  [green][+] Report written:[/green] [bold]{path}[/bold]")
        self.console.print()

    def error(self, msg: str):
        self.console.print(f"  [bold red][X] ERROR:[/bold red] {msg}")

    def info(self, msg: str):
        self.console.print(f"  [cyan][*][/cyan] {msg}")

    def warn(self, msg: str):
        self.console.print(f"  [yellow][!][/yellow] {msg}")
