#!/usr/bin/env python3
"""
Smart Code Analyzer (typed & hardened)

- Multi-stage Prioritize → Deep Dive → Synthesis (+ optional payload gen)
- Code-first by default; YAML/Helm opt-in via flags
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import (
    Any,
    Dict,
    Final,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    TypeAlias,
    TypedDict,
    Literal,
)

import anthropic  # type: ignore[import-untyped]
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from prompts import PromptFactory  # prompt builders

# ---------- Typing helpers ----------

Relevance = Literal["HIGH", "MEDIUM", "LOW", "NONE"]

class InsightTD(TypedDict, total=False):
    finding: str
    line_number: int
    recommendation: str

class APIResponseTD(TypedDict, total=False):
    relevance: Relevance
    insights: List[InsightTD]

FindingDict: TypeAlias = Dict[str, Any]

# ---------- Constants ----------

CODE_EXTS: Final = {".py", ".go", ".java", ".js", ".ts", ".php", ".rb", ".jsx", ".tsx"}
YAML_EXTS: Final = {".yaml", ".yml"}
HELM_EXTS: Final = {".tpl", ".gotmpl"}

CLAUDE_MODEL: Final = "claude-3-5-sonnet-20241022"
DEFAULT_MAX_FILE_BYTES: Final = 500_000  # ~500KB per file
DEFAULT_MAX_FILES: Final = 400           # safety valve for huge repos

SKIP_DIRS: Final = {".git", "node_modules", "__pycache__", "vendor", "build", "dist"}

# ---------- Data structures ----------

@dataclass(slots=True)
class Finding:
    file_path: str
    finding: str
    recommendation: str
    relevance: str
    line_number: Optional[int] = None

    @classmethod
    def from_dict(cls, insight_dict: FindingDict, file_path: str, relevance: str) -> "Finding":
        return cls(
            file_path=file_path,
            relevance=relevance,
            finding=str(insight_dict.get("finding", "N/A")),
            recommendation=str(insight_dict.get("recommendation", "N/A")),
            line_number=insight_dict.get("line_number"),
        )

@dataclass(slots=True)
class AnalysisReport:
    repo_path: str
    question: str
    timestamp: str
    file_count: int
    insights: List[Finding]
    synthesis: str

# ---------- Helpers ----------

def get_api_key() -> str:
    api_key = os.getenv("CLAUDE_API_KEY")
    if not api_key:
        print("Error: CLAUDE_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)
    return api_key

_CODE_FENCE_RE: Final = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)
_JSON_OBJ_RE: Final = re.compile(r"\{.*\}", re.DOTALL)

def parse_json_response(response_text: str) -> Optional[APIResponseTD]:
    """
    Attempt to extract the first JSON object from a model response.
    Strips fenced blocks like ```json ... ```, then parses the first {...}.
    """
    if not response_text:
        return None
    cleaned = _CODE_FENCE_RE.sub("", response_text).strip()
    m = _JSON_OBJ_RE.search(cleaned)
    if not m:
        return None
    try:
        parsed: APIResponseTD = json.loads(m.group(0))
        return parsed
    except json.JSONDecodeError:
        return None

def is_probably_text(path: Path, max_bytes: int) -> bool:
    """
    Quick & safe check: read up to max_bytes and look for binary markers.
    """
    try:
        with path.open("rb") as f:
            b = f.read(min(max_bytes, 8192))
        # Heuristic: presence of NUL or too many non-ASCII control chars
        if b"\x00" in b:
            return False
        # If it decodes as UTF-8 (even with errors='strict' might fail), it's likely text
        try:
            b.decode("utf-8")
            return True
        except UnicodeDecodeError:
            # Maybe it's Latin-1 text; fall back to permissive check
            return all(c >= 9 or c in (10, 13) for c in b)
    except OSError:
        return False

def positive_int(value: str) -> int:
    try:
        iv = int(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError("must be an integer") from e
    if iv <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return iv

def scan_repo_files(
    repo_path: str,
    include_yaml: bool,
    include_helm: bool,
    max_file_bytes: int,
    max_files: int,
) -> List[Path]:
    """
    Scan repository honoring flags and safety valves.
    Skips known large/binary files and limits per-file size and total count.
    """
    repo = Path(repo_path)
    if not repo.is_dir():
        raise ValueError(f"Repository path '{repo_path}' is not a directory")

    allowed_exts = set(CODE_EXTS)
    if include_yaml:
        allowed_exts |= YAML_EXTS
    if include_helm:
        allowed_exts |= HELM_EXTS

    results: List[Path] = []
    for file_path in repo.rglob("*"):
        if len(results) >= max_files:
            break
        if not file_path.is_file():
            continue
        if any(skip in file_path.parts for skip in SKIP_DIRS):
            continue

        suffix = file_path.suffix.lower()
        # Extension gate
        if suffix in CODE_EXTS:
            pass
        elif suffix in YAML_EXTS:
            if not include_yaml:
                continue
        elif suffix in HELM_EXTS:
            if not include_helm:
                continue
        else:
            if suffix not in allowed_exts:
                continue

        try:
            size = file_path.stat().st_size
        except OSError:
            continue
        if size > max_file_bytes:
            continue
        if not is_probably_text(file_path, max_bytes=max_file_bytes):
            continue

        results.append(file_path)

    return sorted(results, key=lambda p: (p.suffix, p.name.lower()))

# ---------- Core ----------

class SmartAnalyzer:
    def __init__(self, console: Console, client: anthropic.Anthropic):
        self.console = console
        self.client = client

    def _call_claude(self, prompt: str, max_tokens: int = 4000) -> Optional[str]:
        try:
            response = self.client.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            # anthropic SDK returns list of content blocks
            return response.content[0].text if response.content else None
        except Exception as e:
            self.console.print(f"[red]API Error: {e}[/red]")
            return None

    def run_prioritization_stage(self, all_files: List[Path], question: str, debug: bool) -> List[Path]:
        self.console.print("[bold]Stage 1: Prioritizing files...[/bold]")
        if not all_files:
            self.console.print("[yellow]No files discovered, skipping prioritization.[/yellow]\n")
            return []

        prompt = PromptFactory.prioritization(all_files, question)
        response_text = self._call_claude(prompt)
        if not response_text:
            return all_files

        if debug:
            self.console.print(Panel(response_text, title="[bold blue]RAW API RESPONSE (Prioritization)[/bold blue]"))

        parsed = parse_json_response(response_text)
        if parsed and isinstance(parsed.get("prioritized_files"), list):
            prioritized_names = set(str(n) for n in parsed["prioritized_files"])
            prioritized_files = [p for p in all_files if p.name in prioritized_names]
            self.console.print(f"[green]✓ Prioritized {len(prioritized_files)} files for deep analysis.[/green]\n")
            return prioritized_files

        self.console.print("[yellow]Could not determine priority, analyzing all files.[/yellow]\n")
        return all_files

    def run_deep_dive_stage(
        self,
        files_to_analyze: List[Path],
        question: str,
        verbose: bool,
        debug: bool
    ) -> List[Finding]:
        self.console.print("[bold]Stage 2: Performing deep dive analysis...[/bold]")
        findings: List[Finding] = []

        for i, file_path in enumerate(files_to_analyze, 1):
            self.console.print(f"[[bold]{i}/{len(files_to_analyze)}[/bold]] Analyzing [cyan]{file_path.name}[/cyan]...")
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                self.console.print(f"   [red]Error reading {file_path.name}: {e}[/red]")
                continue

            suffix = file_path.suffix.lower()
            is_yaml = suffix in YAML_EXTS
            looks_like_helm = any(part in ("templates", "charts") for part in file_path.parts) or ("{{" in content)
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
            if parsed and isinstance(parsed.get("insights"), list):
                relevance = str(parsed.get("relevance", "N/A"))
                file_insights: Sequence[InsightTD] = parsed.get("insights", [])
                self.console.print(f"   Relevance: [bold yellow]{relevance}[/bold yellow], Found [bold]{len(file_insights)}[/bold] insights.")

                if verbose and file_insights:
                    for ins in file_insights:
                        self.console.print(
                            f"     [bold]Finding:[/bold] {ins.get('finding', 'N/A')} "
                            f"(Line: {ins.get('line_number', 'N/A')})"
                        )
                        self.console.print(f"     [bold]Recommendation:[/bold] {ins.get('recommendation', 'N/A')}\n")

                for ins in file_insights:
                    findings.append(Finding.from_dict(ins, str(file_path), relevance))
            else:
                self.console.print("   [yellow]Could not parse a structured response from API.[/yellow]")

            time.sleep(1)  # be nice to the API

        self.console.print("[green]✓ Deep dive analysis complete.[/green]\n")
        return findings

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
        for i, finding in enumerate(top_findings, start=1):
            self.console.print(f"[[bold]{i}/{len(top_findings)}[/bold]] Generating payload for [cyan]{Path(finding.file_path).name}[/cyan]...")
            try:
                lines = Path(finding.file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
                ln = finding.line_number or 1
                start = max(0, ln - 3)
                end = min(len(lines), ln + 2)
                snippet = "\n".join(lines[start:end])
            except OSError:
                snippet = "Could not read code snippet."

            prompt = PromptFactory.payload_generation(finding, snippet)
            response_text = self._call_claude(prompt)
            if not response_text:
                continue

            if debug:
                self.console.print(Panel(response_text, title=f"[bold blue]RAW API RESPONSE (Payloads for {Path(finding.file_path).name})[/bold blue]"))

            parsed = parse_json_response(response_text)
            if parsed:
                rt = parsed.get("red_team_payload", {})  # type: ignore[assignment]
                bt = parsed.get("blue_team_payload", {})  # type: ignore[assignment]
                payload_panel = Panel(
                    f"[bold red]Red Team (Verification)[/bold red]\n"
                    f"  [bold]Payload:[/bold] [yellow]`{rt.get('payload', 'N/A')}`[/yellow]\n"
                    f"  [bold]Explanation:[/bold] {rt.get('explanation', 'N/A')}\n\n"
                    f"[bold green]Blue Team (Defense Test)[/bold green]\n"
                    f"  [bold]Payload:[/bold] [yellow]`{bt.get('payload', 'N/A')}`[/yellow]\n"
                    f"  [bold]Explanation:[/bold] {bt.get('explanation', 'N/A')}",
                    title=f"[bold]Example Payloads for: {finding.finding}[/bold]",
                    border_style="magenta",
                )
                self.console.print(payload_panel)
            time.sleep(1)

# ---------- Output ----------

class OutputManager:
    def __init__(self, console: Console):
        self.console = console

    def display_console_summary(self, report: AnalysisReport, top_n: int) -> None:
        self.console.print(Panel(Markdown(report.synthesis), title="[bold blue]AI-Generated Synthesis[/bold blue]", border_style="blue"))

        if not report.insights:
            return

        rec = Table(title=f"[bold yellow]Top {top_n} Specific Recommendations[/bold yellow]")
        rec.add_column("Recommendation", style="cyan")
        rec.add_column("File", style="magenta")
        for ins in report.insights[:top_n]:
            rec.add_row(ins.recommendation, Path(ins.file_path).name)

        counts = Counter(i.file_path for i in report.insights)
        impacted = Table(title=f"[bold red]Top {top_n} Most Impacted Files[/bold red]")
        impacted.add_column("File", style="magenta")
        impacted.add_column("Findings Count", style="red", justify="right")
        for fp, count in counts.most_common(top_n):
            impacted.add_row(Path(fp).name, str(count))

        self.console.print(f"\nAnalyzed [bold]{report.file_count}[/bold] files and found [bold]{len(report.insights)}[/bold] total insights.\n")
        self.console.print(rec)
        self.console.print(impacted)

    def save_reports(self, report: AnalysisReport, formats: List[str], output_base: Optional[str]) -> None:
        base_path = Path(output_base).with_suffix("") if output_base else Path(
            f"analysis_{Path(report.repo_path).name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        for fmt in formats:
            if fmt == "console":
                continue
            out = base_path.with_suffix(f".{fmt}")
            try:
                if fmt == "markdown":
                    content_md = f"# Analysis for {report.repo_path}\n\n## Question: {report.question}\n\n{report.synthesis}"
                    content = content_md
                elif fmt == "html":
                    content_md = f"# Analysis for {report.repo_path}\n\n## Question: {report.question}\n\n{report.synthesis}"
                    content = (
                        "<!doctype html><meta charset='utf-8'>"
                        "<title>Analysis Report</title>"
                        "<style>body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:900px;margin:40px auto;padding:0 16px;line-height:1.5}</style>"
                        f"<pre>{html.escape(content_md)}</pre>"
                    )
                else:
                    content = ""
                out.write_text(content, encoding="utf-8")
                self.console.print(f"[bold green]✓ Report saved to: {out}[/bold green]")
            except Exception as e:  # pragma: no cover
                self.console.print(f"[red]Error saving {fmt} report: {e}[/red]")

# ---------- CLI ----------

def create_parser() -> argparse.ArgumentParser:
    examples = """
Examples:
  # Code-only (default)
  python smart__.py /path/to/repo "Find security vulnerabilities"

  # Include YAML only
  python smart__.py /path/to/repo "Audit k8s manifests" --include-yaml

  # Include Helm templates (tpl/gotmpl). YAML still excluded unless --include-yaml is also set.
  python smart__.py /path/to/repo "Review helm templating" --include-helm

  # Tighter limits for very large repos
  python smart__.py /path/to/repo "Threat model this app" --max-file-bytes 200000 --max-files 200
    """
    p = argparse.ArgumentParser(
        description="A multi-stage AI code analyzer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples,
    )
    p.add_argument("repo_path", help="Path to the repository to analyze")
    p.add_argument("question", nargs="?", help="Analysis question (prompts if not provided)")
    p.add_argument("-v", "--verbose", action="store_true", help="Print detailed insights for each file as they are found.")
    p.add_argument("--debug", action="store_true", help="Print raw API responses for every call.")
    p.add_argument("--format", nargs="*", default=["console"], choices=["console", "html", "markdown"], help="One or more output formats.")
    p.add_argument("-o", "--output", help='Base output file path (e.g., "report"). Suffix is ignored.')
    p.add_argument("--no-color", action="store_true", help="Disable colorized output.")
    p.add_argument("--top-n", type=positive_int, default=5, help="Number of items for summary tables and payload generation.")
    p.add_argument("--generate_payloads", "--generate-payloads", dest="generate_payloads", action="store_true",
                   help="Generate example Red/Blue team payloads for top findings.")
    p.add_argument("--include-yaml", action="store_true",
                   help="Include .yaml/.yml files (Kubernetes manifests, Helm values). Default: off.")
    p.add_argument("--include-helm", action="store_true",
                   help="Include Helm templates (.tpl/.gotmpl). Default: off. NOTE: .yaml templates stay excluded unless --include-yaml is set.")
    p.add_argument("--max-file-bytes", type=positive_int, default=DEFAULT_MAX_FILE_BYTES,
                   help=f"Skip files larger than this many bytes (default {DEFAULT_MAX_FILE_BYTES}).")
    p.add_argument("--max-files", type=positive_int, default=DEFAULT_MAX_FILES,
                   help=f"Analyze at most this many files (default {DEFAULT_MAX_FILES}).")
    return p

def get_question_interactively(console: Console) -> str:
    console.print("\n[bold cyan]What would you like to analyze about this codebase?[/bold cyan]")
    console.print("[dim]Examples: 'Find security vulnerabilities', 'Suggest performance improvements', 'How can I refactor this code?'[/dim]")
    q = input("Enter your question: ").strip()
    if not q:
        console.print("[red]No question provided. Exiting.[/red]")
        sys.exit(1)
    return q

# ---------- Main ----------

def main() -> None:
    parser = create_parser()
    args = parser.parse_args()

    console = Console(no_color=args.no_color)

    try:
        api_key = get_api_key()
        client = anthropic.Anthropic(api_key=api_key)

        repo_path = args.repo_path
        if not os.path.exists(repo_path):
            console.print(f"[red]Error: Repository path '{repo_path}' does not exist[/red]")
            sys.exit(1)

        question = args.question or get_question_interactively(console)

        console.print(Panel(
            f"[bold]Repository:[/bold] {repo_path}\n[bold]Question:[/bold] {question}",
            title="[bold blue]Dynamic Code Analyzer[/bold blue]"
        ))

        all_files = scan_repo_files(
            repo_path=repo_path,
            include_yaml=bool(args.include_yaml),
            include_helm=bool(args.include_helm),
            max_file_bytes=int(args.max_file_bytes),
            max_files=int(args.max_files),
        )
        console.print(
            f"Found {len(all_files)} total files "
            f"(YAML: {'on' if args.include_yaml else 'off'}, Helm: {'on' if args.include_helm else 'off'})."
            f" Limits: max_file_bytes={args.max_file_bytes}, max_files={args.max_files}\n"
        )

        analyzer = SmartAnalyzer(console, client)

        prioritized_files = analyzer.run_prioritization_stage(all_files, question, args.debug)
        insights = analyzer.run_deep_dive_stage(prioritized_files, question, args.verbose, args.debug)
        synthesis_text = analyzer.run_synthesis_stage(insights, question)

        report = AnalysisReport(
            repo_path=repo_path,
            question=question,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            file_count=len(prioritized_files),
            insights=insights,
            synthesis=synthesis_text,
        )

        out = OutputManager(console)
        if "console" in args.format:
            out.display_console_summary(report, args.top_n)

        file_formats = [f for f in args.format if f != "console"]
        if file_formats:
            out.save_reports(report, file_formats, args.output)

        if args.generate_payloads and report.insights:
            analyzer.run_payload_generation_stage(report.insights[: args.top_n], args.debug)

    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Analysis interrupted by user.[/bold yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()

