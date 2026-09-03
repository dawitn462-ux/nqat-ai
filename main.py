"""
NKAT AI Security Scanner CLI Entrypoint.
Launches security audit reading targets strictly from docs/AUTHORIZED_TARGETS.md.
Free-text CLI target overrides are strictly disallowed to prevent scanning unauthorized hosts.
"""

import argparse
import asyncio
import sys
import os

from dotenv import load_dotenv

load_dotenv()

from scanner.core import SecurityScanner
from scanner.exceptions import ScopeViolationError, ScanConfigError

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


def print_rich_summary(report):
    console = Console()
    console.print("\n[bold cyan]=============================================[/bold cyan]")
    console.print("[bold green]         NKAT AI SECURITY SCAN REPORT        [/bold green]")
    console.print("[bold cyan]=============================================[/bold cyan]\n")

    summary_text = (
        f"[bold]Target URL (from Policy):[/bold] {report.target_url}\n"
        f"[bold]Scan ID:[/bold] {report.scan_id}\n"
        f"[bold]Duration:[/bold] {report.summary.scan_duration_seconds}s\n"
        f"[bold]Endpoints Scanned:[/bold] {report.summary.total_endpoints_scanned}\n"
        f"[bold]Total Findings:[/bold] {report.summary.total_vulnerabilities}"
    )
    console.print(Panel(summary_text, title="[bold white]Audit Summary[/bold white]", border_style="blue"))

    if report.structured_findings:
        table = Table(title="[bold yellow]Structured Vulnerability Findings ({target, check_name, severity, evidence, timestamp})[/bold yellow]")
        table.add_column("Target", style="cyan", width=28)
        table.add_column("Check Name", style="bold white")
        table.add_column("Severity", justify="center")
        table.add_column("Sanitized Evidence", style="dim white")

        severity_colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim white",
        }

        for finding in report.structured_findings:
            sev_str = finding.severity
            color = severity_colors.get(sev_str, "white")
            table.add_row(
                finding.target,
                finding.check_name,
                f"[{color}]{sev_str}[/{color}]",
                finding.evidence,
            )

        console.print(table)
    else:
        console.print("[bold green]No security vulnerabilities detected.[/bold green]")


async def main_async():
    parser = argparse.ArgumentParser(
        description="NKAT AI Security Scanner CLI (Reads scope strictly from docs/AUTHORIZED_TARGETS.md)"
    )
    parser.add_argument(
        "--policy",
        default="docs/AUTHORIZED_TARGETS.md",
        help="Path to authorization policy document (default: docs/AUTHORIZED_TARGETS.md)",
    )
    parser.add_argument("--output", default="data", help="Output directory for reports")
    parser.add_argument("--strict", action="store_true", help="Enable strict port enforcement")

    args = parser.parse_args()

    # Scanner reads target strictly from policy file
    scanner = SecurityScanner(
        policy_path=args.policy,
        output_dir=args.output,
        strict_enforcement=args.strict if args.strict else None,
    )

    try:
        report = await scanner.execute_scan()
        if HAS_RICH:
            print_rich_summary(report)
        else:
            print(f"\n[+] Scan Complete. Total Findings: {len(report.findings)}")
    except ScopeViolationError as err:
        print(f"\n[!] SECURITY SCOPE ERROR: {err}", file=sys.stderr)
        sys.exit(1)
    except ScanConfigError as err:
        print(f"\n[!] CONFIGURATION ERROR: {err}", file=sys.stderr)
        sys.exit(1)


def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
