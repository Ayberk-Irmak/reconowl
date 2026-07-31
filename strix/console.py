"""Rich-based console helpers: banner, phase headers, status, summary table.

Kept separate from logic so phases just call ``ui.info(...)`` etc. and never
build presentation strings themselves.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .models import ScanResult, Severity

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_BANNER = r"""
   _____ _        _
  / ____| |      (_)
 | (___ | |_ _ __ ___  __
  \___ \| __| '__| \ \/ /
  ____) | |_| |  | |>  <
 |_____/ \__|_|  |_/_/\_\
"""


class UI:
    """Thin wrapper around a rich Console with Strix conventions."""

    def __init__(self, quiet: bool = False, no_color: bool = False) -> None:
        self.console = Console(no_color=no_color, highlight=False)
        self.quiet = quiet

    def banner(self) -> None:
        if self.quiet:
            return
        text = Text(_BANNER, style="bold magenta")
        text.append(f"\n  recon → scan → report   v{__version__}\n", style="dim")
        self.console.print(text)

    def phase(self, name: str) -> None:
        if self.quiet:
            return
        self.console.print()
        self.console.print(Panel(f"[bold]{name}[/bold]", expand=False, border_style="magenta"))

    def info(self, msg: str) -> None:
        if not self.quiet:
            self.console.print(f"[dim]·[/dim] {msg}")

    def good(self, msg: str) -> None:
        if not self.quiet:
            self.console.print(f"[green]✓[/green] {msg}")

    def warn(self, msg: str) -> None:
        self.console.print(f"[yellow]![/yellow] {msg}")

    def error(self, msg: str) -> None:
        self.console.print(f"[red]✗[/red] {msg}")

    def finding(self, severity: Severity, title: str, location: str = "", cvss: float | None = None) -> None:
        if self.quiet:
            return
        style = _SEVERITY_STYLE[severity]
        tag = f"[{style}] {severity.label.upper():^8} [/]"
        score = f" [bold]{cvss:.1f}[/bold]" if cvss is not None else ""
        loc = f" [dim]{location}[/dim]" if location else ""
        self.console.print(f"{tag}{score} {title}{loc}")

    def diff(self, diff_result, old_label: str) -> None:
        c = diff_result.counts()
        self.console.print()
        self.console.print(
            f"[bold]Diff vs[/bold] [dim]{old_label}[/dim]:  "
            f"[green]+{c['new']} new[/green]  "
            f"[cyan]-{c['fixed']} fixed[/cyan]  "
            f"[yellow]~{c['changed']} changed[/yellow]  "
            f"[dim]{c['unchanged']} unchanged[/dim]"
        )
        for f in diff_result.new:
            score = f.get("cvss_score")
            score_s = f"{score:.1f}" if isinstance(score, (int, float)) else "  -"
            self.console.print(f"  [green]NEW[/green]   [bold]{score_s}[/bold] {f.get('title')} "
                               f"[dim]{f.get('location', '')}[/dim]")
        for f in diff_result.fixed:
            self.console.print(f"  [cyan]FIXED[/cyan] {f.get('title')} "
                               f"[dim]{f.get('location', '')}[/dim]")

    def summary(self, result: ScanResult) -> None:
        counts = result.severity_counts()
        table = Table(title="Findings by severity", show_header=True, header_style="bold")
        table.add_column("Severity")
        table.add_column("Count", justify="right")
        for sev in reversed(Severity):
            style = _SEVERITY_STYLE[sev]
            table.add_row(f"[{style}]{sev.label}[/]", str(counts[sev.label]))
        self.console.print()
        self.console.print(table)

        assets = Table(title="Assets discovered", show_header=True, header_style="bold")
        assets.add_column("Asset")
        assets.add_column("Count", justify="right")
        assets.add_row("Subdomains", str(len(result.subdomains)))
        assets.add_row("Open ports", str(len(result.ports)))
        assets.add_row("Web endpoints", str(len(result.endpoints)))
        assets.add_row("URLs", str(len(result.urls)))
        self.console.print(assets)
