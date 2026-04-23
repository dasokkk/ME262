"""
Console UI — Rich-powered terminal interface.

Provides styled banners, an interactive setup wizard, live scan output,
IDS alerts, AI analyst panels, and interactive prompts.
"""

import time
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.prompt import Prompt, Confirm, IntPrompt, FloatPrompt
from rich import box
from rich.text import Text


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
        
        self.console.print(
            Rule("[bold yellow]⚙  Setup Wizard[/bold yellow]", style="yellow")
        )
        self.console.print()

        
        self.console.print(
            "  [bold]1.[/bold] [cyan]Target Host or IP[/cyan]"
        )
        self.console.print(
            "     [dim]Enter a hostname (e.g., domain.com) or an IP address.[/dim]"
        )
        target = Prompt.ask(
            "     [cyan]Target[/cyan]",
            default=preset_target or "example.com",
        )
        self.console.print()

        
        self.console.print(
            "  [bold]2.[/bold] [cyan]Scan profile[/cyan]"
        )

        profile_info = {
            "aggressive": (
                "🔥 Aggressive",
                "High rate (20/s), low timeout, fixed timing — fast & loud",
            ),
            "normal": (
                "⚡ Normal",
                "Moderate rate (3/s), jitter timing — balanced",
            ),
            "stealth": (
                "🤫 Stealth",
                "Low rate (0.5/s), random ports, long-tail delays — quiet",
            ),
        }

        for i, prof in enumerate(profiles, 1):
            name, desc = profile_info.get(prof, (prof, ""))
            marker = "[bold green]→[/bold green]" if prof == "normal" else " "
            self.console.print(f"     {marker} [bold]{i}.[/bold] {name}")
            self.console.print(f"        [dim]{desc}[/dim]")

        profile_map = {str(i): p for i, p in enumerate(profiles, 1)}
        profile_map.update({p: p for p in profiles})  # also accept names

        raw = Prompt.ask(
            "     [cyan]Choose profile[/cyan] [dim](1/2/3 or name)[/dim]",
            default=preset_profile or "normal",
        )
        profile = profile_map.get(raw.lower().strip(), raw.lower().strip())
        if profile not in profiles:
            self.warn(f"Unknown profile '{profile}', defaulting to 'normal'")
            profile = "normal"
        self.console.print()

        
        self.console.print(
            "  [bold]3.[/bold] [cyan]Port strategy[/cyan]"
        )
        strategies = {
            "top":        "Well-known ports (22, 80, 443, 3389 …)",
            "random":     "50 random ports from full range",
            "sequential": "Ports 1–1024 in order",
            "weighted":   "Top ports + random high ports",
        }
        for key, desc in strategies.items():
            self.console.print(f"       [bold]{key:<12}[/bold] [dim]{desc}[/dim]")

        port_strategy = Prompt.ask(
            "     [cyan]Strategy[/cyan]",
            default="top",
            choices=list(strategies.keys()),
        )
        self.console.print()

        
        self.console.print(
            "  [bold]4.[/bold] [cyan]Scan rate[/cyan] [dim](probes per second)[/dim]"
        )
        self.console.print(
            "     [dim]Press Enter to use the profile default.[/dim]"
        )
        rate_raw = Prompt.ask(
            "     [cyan]Rate[/cyan]",
            default="",
        )
        rate = None
        if rate_raw.strip():
            try:
                rate = float(rate_raw)
            except ValueError:
                self.warn("Invalid number, using profile default.")
        self.console.print()

        
        self.console.print(
            "  [bold]5.[/bold] [cyan]Probe timeout[/cyan] [dim](seconds)[/dim]"
        )
        self.console.print(
            "     [dim]Press Enter to use the profile default.[/dim]"
        )
        timeout_raw = Prompt.ask(
            "     [cyan]Timeout[/cyan]",
            default="",
        )
        timeout = None
        if timeout_raw.strip():
            try:
                timeout = float(timeout_raw)
            except ValueError:
                self.warn("Invalid number, using profile default.")
        self.console.print()

        #
        self.console.print(
            "  [bold]6.[/bold] [cyan]Ollama AI model[/cyan]"
        )
        self.console.print(
            "     [dim]The LLM model for the AI analyst (must be pulled in Ollama).[/dim]"
        )
        model = Prompt.ask(
            "     [cyan]Model[/cyan]",
            default=preset_model or "llama3.2",
        )
        self.console.print()

        
        self.console.print(
            Rule("[bold yellow]📋  Configuration Summary[/bold yellow]", style="yellow")
        )
        self.console.print()

        summary = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
        summary.add_column("Key", style="cyan", min_width=16)
        summary.add_column("Value", style="bold white")

        summary.add_row("Target", target)
        summary.add_row("Profile", profile)
        summary.add_row("Port Strategy", port_strategy)
        summary.add_row("Scan Rate", str(rate) + " /s" if rate else "(profile default)")
        summary.add_row("Timeout", str(timeout) + "s" if timeout else "(profile default)")
        summary.add_row("AI Model", model)

        self.console.print(summary)
        self.console.print()

        return {
            "target": target,
            "model": model,
            "profile": profile,
            "port_strategy": port_strategy,
            "rate": rate,
            "timeout": timeout,
        }

    

    def show_config(self, target: str, params: Dict, model: str,
                    profile: str = "custom"):
        table = Table(
            title="⚙  Active Configuration",
            box=box.ROUNDED,
            title_style="bold white",
            border_style="cyan",
        )
        table.add_column("Parameter", style="cyan", min_width=16)
        table.add_column("Value", style="green")

        table.add_row("Target", target)
        table.add_row("Profile", profile)
        for k, v in params.items():
            table.add_row(k.replace('_', ' ').title(), str(v))
        table.add_row("AI Model", model)

        self.console.print(table)
        self.console.print()

    

    def scan_event(self, event):
        
        port_str = f"{event.dst_port}/tcp"
        ts = time.strftime("%H:%M:%S", time.localtime(event.timestamp))

        if event.result == "open":
            icon, style = "✅", "bold green"
        elif event.result == "closed":
            icon, style = "·", "dim"
        elif event.result == "filtered":
            icon, style = "🔒", "yellow"
        else:
            icon, style = "⚠", "red"

        self.console.print(
            f"  {icon} [{ts}]  {port_str:<12} "
            f"{event.result:<10} {event.duration_ms:>7.1f}ms  "
            f"{event.scan_type}",
            style=style,
            highlight=False,
        )

    

    def ids_status(self, stats: Dict):
        parts = [f"[cyan]{k}[/cyan]={v}" for k, v in stats.items()]
        self.console.print(
            f"  [dim]📡 Suricata IDS │ {' │ '.join(parts)}[/dim]",
            highlight=False,
        )

    

    def suricata_alert(self, alerts: List):
        self.console.print()
        self.console.print(
            Rule(
                f"[bold red]⚠️  SURICATA IDS ALERT ({len(alerts)}) — SCAN PAUSED  ⚠️[/bold red]",
                style="red",
            )
        )
        self.console.print()

        table = Table(
            title="Real-Time Signatures Triggered",
            box=box.SIMPLE_HEAVY,
            border_style="yellow",
        )
        table.add_column("Sig ID", style="cyan")
        table.add_column("Signature Name", style="white")
        table.add_column("Category", style="yellow")
        table.add_column("Dest Port", style="red", justify="right")

        for alert in alerts:
            table.add_row(
                str(alert.signature_id), 
                alert.signature, 
                alert.category,
                str(alert.dst_port)
            )

        self.console.print(table)
        
        
        if alerts and alerts[0].rule_logic != "Rule logic unavailable.":
            self.console.print()
            self.console.print("  [bold]Extracted Rule Logic (Reason for detection):[/bold]")
            self.console.print(f"  [yellow]{alerts[0].rule_logic}[/yellow]")
        
        self.console.print()

    

    def ai_message(self, message: str):
        self.console.print()
        panel = Panel(
            message,
            title="🤖 AI Analyst",
            border_style="blue",
            padding=(1, 2),
        )
        self.console.print(panel)

    

    def user_prompt(self) -> str:
        self.console.print()
        return Prompt.ask(
            "[bold cyan]🎯 What should we do now?[/bold cyan]  "
            "[dim](type 'resume' to continue, 'quit' to stop)[/dim]"
        )

    

    def param_change(self, params: Dict):
        if not params:
            return
        self.console.print()
        self.console.print(
            "  [bold green]✓ Parameter adjustments applied:[/bold green]"
        )
        for k, v in params.items():
            self.console.print(f"    [green]▸[/green] {k} → {v}")

    

    def resuming(self):
        self.console.print()
        self.console.print(
            Rule("[bold green]▶  SCAN RESUMING[/bold green]", style="green")
        )
        self.console.print()

    

    def scan_complete(self, stats: Dict, open_ports: List[int] = None):
        self.console.print()
        self.console.print(
            Rule("─────────────────────────────── [bold cyan]SCAN COMPLETE[/bold cyan] ─────────", style="cyan")
        )
        self.console.print()
        
        #open ports table
        if open_ports:
            services = {
                21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
                80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
                139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
                993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1723: "pptp",
                3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
                5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
                8888: "sun-answerbook", 9090: "zeus-admin", 11434: "ollama",
                27017: "mongodb"
            }
            
            self.console.print("  [bold white]PORT      STATE  SERVICE[/bold white]")
            for port in sorted(set(open_ports)):
                svc = services.get(port, "unknown")
                self.console.print(f"  [cyan]{port}/tcp[/cyan]".ljust(18) + f" [bold green]open[/bold green]   {svc}")
            self.console.print()
            
        if stats:
            table = Table(box=box.ROUNDED, border_style="cyan")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="white")
            for k, v in stats.items():
                table.add_row(str(k), str(v))
            self.console.print(table)
        self.console.print()

    

    def error(self, msg: str):
        self.console.print(f"  [bold red]✗ ERROR:[/bold red] {msg}")

    def info(self, msg: str):
        self.console.print(f"  [cyan]ℹ[/cyan]  {msg}")

    def warn(self, msg: str):
        self.console.print(f"  [yellow]⚠[/yellow]  {msg}")
