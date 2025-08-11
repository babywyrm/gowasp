#!/usr/bin/env python3
"""
A multi-stage, 'lite' dynamic code analyzer that uses a Prioritize-Analyze-Synthesize
pipeline to provide holistic insights into a codebase, with an optional payload
generation stage for verification and testing.

Requires the 'rich' and 'anthropic' libraries:
pip install rich anthropic
"""

from __future__ import annotations

import os
import re
import sys
import json
import time
import html
import argparse
from pathlib import Path
from collections import Counter
from typing import List, Dict, Optional, Any, TypeAlias
from dataclasses import dataclass
from datetime import datetime

import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

# Prompt builders (separate module)
from prompts import PromptFactory

# --- Constants & Type Aliases ---
# Default: code-only. YAML/Helm are opt-in via CLI flags.
CODE_EXTS = {'.py', '.go', '.java', '.js', '.ts', '.php', '.rb', '.jsx', '.tsx'}
YAML_EXTS = {'.yaml', '.yml'}
HELM_EXTS = {'.tpl', '.gotmpl'}

CLAUDE_MODEL = "claude-3-5-sonnet-20241022"
FindingDict: TypeAlias = Dict[str, Any]


# --- Data Structures ---
@dataclass
class Finding:
    file_path: str
    finding: str
    recommendation: str
    relevance: str
    line_number: Optional[int] = None

    @classmethod
    def from_dict(cls, insight_dict: FindingDict, file_path: str, relevance: str) -> 'Finding':
        return cls(
            file_path=file_path,
            relevance=relevance,
            finding=insight_dict.get('finding', 'N/A'),
            recommendation=insight_dict.get('recommendation', 'N/A'),
            line_number=insight_dict.get('line_number'),
        )


@dataclass
class AnalysisReport:
    repo_path: str
    question: str
    timestamp: str
    file_count: int
    insights: List[Finding]
    synthesis: str


# --- Helper Functions ---
def get_api_key() -> str:
    api_key = os.getenv('CLAUDE_API_KEY')
    if not api_key:
        print("Error: CLAUDE_API_KEY environment variable not set.")
        sys.exit(1)
    return api_key


def parse_json_response(response_text: str) -> Optional[Dict]:
    try:
        match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
    except (json.JSONDecodeError):
        pass
    return None


def scan_repo_files(repo_path: str, include_yaml: bool, include_helm: bool) -> List[Path]:
    """Scans a repository for supported file types, honoring YAML/Helm flags."""
    repo = Path(repo_path)
    files: List[Path] = []
    skip_dirs = {'.git', 'node_modules', '__pycache__', 'vendor', 'build', 'dist'}
    allowed_exts = set(CODE_EXTS)
    if include_yaml:
        allowed_exts |= YAML_EXTS
    if include_helm:
        allowed_exts |= HELM_EXTS

    for file_path in repo.rglob("*"):
        if not file_path.is_file():
            continue
        if any(skip in file_path.parts for skip in skip_dirs):
            continue

        suffix = file_path.suffix.lower()

        # Respect opt-in behavior
        if suffix in CODE_EXTS:
            pass  # always allowed
        elif suffix in YAML_EXTS and not include_yaml:
            continue
        elif suffix in HELM_EXTS and not include_helm:
            continue
        else:
            # if the suffix isn't in any known set, skip
            if suffix not in allowed_exts:
                continue

        files.append(file_path)

    return sorted(files)


# --- Core Logic Classes ---
class SmartAnalyzer:
    def __init__(self, console: Console, client: anthropic.Anthropic):
        self.console = console
        self.client = client

    def _call_claude(self, prompt: str, max_tokens: int = 4000) -> Optional[str]:
        try:
            response = self.client.messages.create(
                model=CLAUDE_MODEL, max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text
        except Exception as e:
            self.console.print(f"[red]API Error: {e}[/red]")
            return None

    def run_prioritization_stage(self, all_files: List[Path], question: str, debug: bool) -> List[Path]:
        self.console.print("[bold]Stage 1: Prioritizing files...[/bold]")
        prompt = PromptFactory.prioritization(all_files, question)
        response_text = self._call_claude(prompt)
        if not response_text:
            return all_files

        if debug:
            self.console.print(Panel(response_text, title="[bold blue]RAW API RESPONSE (Prioritization)[/bold blue]"))

        parsed = parse_json_response(response_text)
        if parsed and "prioritized_files" in parsed and isinstance(parsed["prioritized_files"], list):
            prioritized_names = set(parsed["prioritized_files"])
            prioritized_files = [p for p in all_files if p.name in prioritized_names]
            self.console.print(f"[green]✓ Prioritized {len(prioritized_files)} files for deep analysis.[/green]\n")
            return prioritized_files

        self.console.print("[yellow]Could not determine priority, analyzing all files.[/yellow]\n")
        return all_files

    def run_deep_dive_stage(self, files_to_analyze: List[Path], question: str, verbose: bool, debug: bool) -> List[Finding]:
        self.console.print("[bold]Stage 2: Performing deep dive analysis...[/bold]")
        all_findings: List[Finding] = []

        for i, file_path in enumerate(files_to_analyze, 1):
            self.console.print(f"[[bold]{i}/{len(files_to_analyze)}[/bold]] Analyzing [cyan]{file_path.name}[/cyan]...")
            try:
                content = file_path.read_text(encoding='utf-8', errors='replace')
            except IOError as e:
                self.console.print(f"   [red]Error reading file {file_path.name}: {e}[/red]")
                continue

            suffix = file_path.suffix.lower()
            is_yaml = suffix in YAML_EXTS
            looks_like_helm = any(part in ('templates', 'charts') for part in file_path.parts) or '{{' in content
            is_helm_template = looks_like_helm and (is_yaml or suffix in HELM_EXTS)

            if is_helm_template:
                prompt = PromptFactory.deep_dive_helm(file_path, content, question)
            elif is_yaml:
                prompt = PromptFactory.deep_dive_yaml(file_path, content, question)
            else:
                prompt = PromptFactory.deep_dive(file_path, content, question)

            response_text = self._call_claude(prompt)
            if not response_text:
                continue

            if debug:
                self.console.print(Panel(response_text, title=f"[bold blue]RAW API RESPONSE ({file_path.name})[/bold blue]"))

            parsed = parse_json_response(response_text)
            if parsed and 'insights' in parsed:
                relevance = parsed.get('relevance', 'N/A')
                file_insights = parsed.get('insights', [])
                self.console.print(f"   Relevance: [bold yellow]{relevance}[/bold yellow], Found [bold]{len(file_insights)}[/bold] insights.")

                if verbose and file_insights:
                    for insight in file_insights:
                        self.console.print(f"     [bold]Finding:[/bold] {insight.get('finding', 'N/A')} (Line: {insight.get('line_number', 'N/A')})")
                        self.console.print(f"     [bold]Recommendation:[/bold] {insight.get('recommendation', 'N/A')}\n")

                for insight in file_insights:
                    all_findings.append(Finding.from_dict(insight, str(file_path), relevance))
            else:
                self.console.print("   [yellow]Could not parse a structured response from API.[/yellow]")
            time.sleep(1)

        self.console.print("[green]✓ Deep dive analysis complete.[/green]\n")
        return all_findings

    def run_synthesis_stage(self, all_findings: List[Finding], question: str) -> str:
        self.console.print("[bold]Stage 3: Synthesizing results into a final report...[/bold]")
        if not all_findings:
            return "No insights were found, so no synthesis could be performed."

        prompt = PromptFactory.synthesis(all_findings, question)
        response_text = self._call_claude(prompt)
        self.console.print("[green]✓ Synthesis complete.[/green]\n")
        return response_text or "Failed to generate a synthesis report."

    def run_payload_generation_stage(self, top_findings: List[Finding], debug: bool) -> None:
        self.console.print("[bold]Optional Stage: Generating example payloads...[/bold]")
        for i, finding in enumerate(top_findings):
            self.console.print(f"[[bold]{i+1}/{len(top_findings)}[/bold]] Generating payload for finding in [cyan]{Path(finding.file_path).name}[/cyan]...")
            try:
                content_lines = Path(finding.file_path).read_text(encoding='utf-8').splitlines()
                line_num = finding.line_number or 1
                start = max(0, line_num - 3)
                end = min(len(content_lines), line_num + 2)
                code_snippet = "\n".join(content_lines[start:end])
            except Exception:
                code_snippet = "Could not read code snippet."

            prompt = PromptFactory.payload_generation(finding, code_snippet)
            response_text = self._call_claude(prompt)
            if not response_text:
                continue

            if debug:
                self.console.print(Panel(response_text, title=f"[bold blue]RAW API RESPONSE (Payloads for {Path(finding.file_path).name})[/bold blue]"))

            parsed = parse_json_response(response_text)
            if parsed:
                rt_payload = parsed.get("red_team_payload", {})
                bt_payload = parsed.get("blue_team_payload", {})
                payload_panel = Panel(
                    f"[bold red]Red Team (Verification)[/bold red]\n"
                    f"  [bold]Payload:[/bold] [yellow]`{rt_payload.get('payload', 'N/A')}`[/yellow]\n"
                    f"  [bold]Explanation:[/bold] {rt_payload.get('explanation', 'N/A')}\n\n"
                    f"[bold green]Blue Team (Defense Test)[/bold green]\n"
                    f"  [bold]Payload:[/bold] [yellow]`{bt_payload.get('payload', 'N/A')}`[/yellow]\n"
                    f"  [bold]Explanation:[/bold] {bt_payload.get('explanation', 'N/A')}",
                    title=f"[bold]Example Payloads for: {finding.finding}[/bold]",
                    border_style="magenta"
                )
                self.console.print(payload_panel)
            time.sleep(1)


class OutputManager:
    def __init__(self, console: Console):
        self.console = console

    def display_console_summary(self, report: AnalysisReport, top_n: int) -> None:
        self.console.print(Panel(Markdown(report.synthesis), title="[bold blue]AI-Generated Synthesis[/bold blue]", border_style="blue"))

        if not report.insights:
            return

        recommendations_table = Table(title=f"[bold yellow]Top {top_n} Specific Recommendations[/bold yellow]")
        recommendations_table.add_column("Recommendation", style="cyan")
        recommendations_table.add_column("File", style="magenta")
        for insight in report.insights[:top_n]:
            recommendations_table.add_row(insight.recommendation, Path(insight.file_path).name)

        file_counts = Counter(i.file_path for i in report.insights)
        impacted_files_table = Table(title=f"[bold red]Top {top_n} Most Impacted Files[/bold red]")
        impacted_files_table.add_column("File", style="magenta")
        impacted_files_table.add_column("Findings Count", style="red", justify="right")
        for file_path, count in file_counts.most_common(top_n):
            impacted_files_table.add_row(Path(file_path).name, str(count))

        self.console.print(f"\nAnalyzed [bold]{report.file_count}[/bold] files and found [bold]{len(report.insights)}[/bold] total insights.\n")
        self.console.print(recommendations_table)
        self.console.print(impacted_files_table)

    def save_reports(self, report: AnalysisReport, formats: List[str], output_base: Optional[str]) -> None:
        if not output_base:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            repo_name = Path(report.repo_path).name
            base_path = Path(f"analysis_{repo_name}_{timestamp}")
        else:
            base_path = Path(output_base).with_suffix('')

        for fmt in formats:
            if fmt == 'console':
                continue
            output_path = base_path.with_suffix(f".{fmt}")
            try:
                if fmt == 'markdown':
                    content_md = f"# Analysis for {report.repo_path}\n\n## Question: {report.question}\n\n{report.synthesis}"
                    content = content_md
                elif fmt == 'html':
                    content_md = f"# Analysis for {report.repo_path}\n\n## Question: {report.question}\n\n{report.synthesis}"
                    content = (
                        "<!doctype html><meta charset='utf-8'>"
                        "<title>Analysis Report</title>"
                        "<style>body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:900px;margin:40px auto;padding:0 16px;line-height:1.5}</style>"
                        f"<pre>{html.escape(content_md)}</pre>"
                    )
                else:
                    content = ""

                output_path.write_text(content, encoding='utf-8')
                self.console.print(f"[bold green]✓ Report saved to: {output_path}[/bold green]")
            except Exception as e:
                self.console.print(f"[red]Error saving {fmt} report: {e}[/red]")


def create_parser() -> argparse.ArgumentParser:
    examples = """
Examples:
  # Code-only (default)
  python smart__.py /path/to/repo "Find security vulnerabilities"

  # Include YAML only
  python smart__.py /path/to/repo "Audit k8s manifests" --include-yaml

  # Include Helm templates (tpl/gotmpl). YAML still excluded unless --include-yaml is also set.
  python smart__.py /path/to/repo "Review helm templating" --include-helm

  # Verbose + debug
  python smart__.py /path/to/repo "How can I refactor this?" -v --debug
    """
    parser = argparse.ArgumentParser(description="A multi-stage AI code analyzer.",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=examples)
    parser.add_argument('repo_path', help='Path to the repository to analyze')
    parser.add_argument('question', nargs='?', help='Analysis question (prompts if not provided)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print detailed insights for each file as they are found.')
    parser.add_argument('--debug', action='store_true', help='Print raw API responses for every call.')
    parser.add_argument('--format', nargs='*', default=['console'], choices=['console', 'html', 'markdown'], help='One or more output formats.')
    parser.add_argument('-o', '--output', help='Base output file path (e.g., "report"). Suffix is ignored.')
    parser.add_argument('--no-color', action='store_true', help='Disable colorized output.')
    parser.add_argument('--top-n', type=int, default=5, help='Number of items for summary tables and payload generation.')
    parser.add_argument('--generate_payloads', '--generate-payloads', dest='generate_payloads', action='store_true',
                        help='Generate example Red/Blue team payloads for top findings.')
    parser.add_argument('--include-yaml', action='store_true',
                        help='Include .yaml/.yml files (Kubernetes manifests, Helm values). Default: off.')
    parser.add_argument('--include-helm', action='store_true',
                        help='Include Helm templates (.tpl/.gotmpl). Default: off. NOTE: .yaml templates stay excluded unless --include-yaml is set.')
    return parser


def get_question_interactively(console: Console) -> str:
    console.print("\n[bold cyan]What would you like to analyze about this codebase?[/bold cyan]")
    console.print("[dim]Examples: 'Find security vulnerabilities', 'Suggest performance improvements', 'How can I refactor this code?'[/dim]")
    question = input("Enter your question: ").strip()
    if not question:
        console.print("[red]No question provided. Exiting.[/red]")
        sys.exit(1)
    return question


def main() -> None:
    parser = create_parser()
    args = parser.parse_args()

    console = Console(no_color=args.no_color)

    try:
        api_key = get_api_key()
        client = anthropic.Anthropic(api_key=api_key)

        if not os.path.exists(args.repo_path):
            console.print(f"[red]Error: Repository path '{args.repo_path}' does not exist[/red]")
            sys.exit(1)

        question = args.question or get_question_interactively(console)

        console.print(Panel(f"[bold]Repository:[/bold] {args.repo_path}\n[bold]Question:[/bold] {question}",
                            title="[bold blue]Dynamic Code Analyzer[/bold blue]"))

        all_files = scan_repo_files(args.repo_path, include_yaml=args.include_yaml, include_helm=args.include_helm)
        console.print(f"Found {len(all_files)} total files (YAML: {'on' if args.include_yaml else 'off'}, Helm: {'on' if args.include_helm else 'off'}).\n")

        analyzer = SmartAnalyzer(console, client)

        prioritized_files = analyzer.run_prioritization_stage(all_files, question, args.debug)
        all_insights = analyzer.run_deep_dive_stage(prioritized_files, question, args.verbose, args.debug)
        synthesis_text = analyzer.run_synthesis_stage(all_insights, question)

        report = AnalysisReport(
            repo_path=args.repo_path, question=question,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            file_count=len(prioritized_files), insights=all_insights,
            synthesis=synthesis_text
        )

        output_manager = OutputManager(console)
        if 'console' in args.format:
            output_manager.display_console_summary(report, args.top_n)

        file_formats = [f for f in args.format if f != 'console']
        if file_formats:
            output_manager.save_reports(report, file_formats, args.output)

        if args.generate_payloads and report.insights:
            analyzer.run_payload_generation_stage(report.insights[:args.top_n], args.debug)

    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Analysis interrupted by user.[/bold yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()

