#!/usr/bin/env python3
"""
Smart Code Analyzer (full features + caching)

Stages:
  1. Prioritization
  2. Deep Dive
  3. Synthesis
  4. (Optional) Payload Generation
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import sys
import time
from dataclasses import dataclass, asdict
# UPDATED: Added 'timezone' for compatibility with older Python versions
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Final, List, Optional, Sequence

import anthropic  # type: ignore
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from prompts import PromptFactory  # prompt builders

# ---------- Constants ----------
CLAUDE_MODEL: Final = "claude-3-5-sonnet-20241022"
DEFAULT_MAX_FILE_BYTES: Final = 500_000
DEFAULT_MAX_FILES: Final = 400
SKIP_DIRS: Final = {".git", "node_modules", "__pycache__", "vendor", "build", "dist"}
CODE_EXTS: Final = {".py", ".go", ".java", ".js", ".ts", ".php", ".rb", ".jsx", ".tsx"}
YAML_EXTS: Final = {".yaml", ".yml"}
HELM_EXTS: Final = {".tpl", ".gotmpl"}

# ---------- Data structures ----------
@dataclass
class ConversationLog:
    stage: str
    file: Optional[str]
    prompt: str
    raw_response: str
    parsed: Optional[dict]
    timestamp: str

@dataclass(slots=True)
class Finding:
    file_path: str
    finding: str
    recommendation: str
    relevance: str
    impact: str
    confidence: str
    effort: str
    line_number: Optional[int] = None

    @classmethod
    def from_dict(cls, d: dict, file_path: str, relevance: str) -> Finding:
        return cls(
            file_path=file_path,
            relevance=relevance,
            finding=str(d.get("finding", "N/A")),
            recommendation=str(d.get("recommendation", "N/A")),
            impact=str(d.get("impact", "N/A")),
            confidence=str(d.get("confidence", "N/A")),
            effort=str(d.get("effort", "N/A")),
            line_number=d.get("line_number"),
        )

@dataclass(slots=True)
class AnalysisReport:
    repo_path: str
    question: str
    timestamp: str
    file_count: int
    insights: List[Finding]
    synthesis: str

# ---------- Cache Manager ----------
class CacheManager:
    def __init__(self, cache_dir: str, use_cache: bool = True):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.use_cache = use_cache
        self.session_logs: List[ConversationLog] = []

    def _hash_key(self, stage: str, file: Optional[str], prompt: str) -> str:
        h = hashlib.sha256()
        h.update(f"{stage}|{file or ''}|{prompt}".encode("utf-8"))
        return h.hexdigest()[:16]

    def get(self, stage: str, file: Optional[str], prompt: str) -> Optional[ConversationLog]:
        if not self.use_cache: return None
        key = self._hash_key(stage, file, prompt)
        path = self.cache_dir / f"{key}.json"
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return ConversationLog(**data)
            except Exception: return None
        return None

    def save(self, stage: str, file: Optional[str], prompt: str, raw: str, parsed: Optional[dict]) -> ConversationLog:
        entry = ConversationLog(
            stage=stage, file=file, prompt=prompt, raw_response=raw,
            # UPDATED: Changed to timezone.utc for compatibility
            parsed=parsed, timestamp=datetime.now(timezone.utc).isoformat(),
        )
        key = self._hash_key(stage, file, prompt)
        path = self.cache_dir / f"{key}.json"
        path.write_text(json.dumps(asdict(entry), indent=2), encoding="utf-8")
        self.session_logs.append(entry)
        return entry

    def save_session_log(self) -> None:
        if not self.session_logs: return
        # UPDATED: Changed to timezone.utc for compatibility
        session_file = self.cache_dir / f"session_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        data = [asdict(log) for log in self.session_logs]
        session_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

# ---------- Helpers ----------
def get_api_key() -> str:
    api_key = os.getenv("CLAUDE_API_KEY")
    if not api_key:
        print("Error: CLAUDE_API_KEY not set.", file=sys.stderr)
        sys.exit(1)
    return api_key

_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)
def parse_json_response(response_text: str) -> Optional[dict]:
    if not response_text: return None
    cleaned = _CODE_FENCE_RE.sub("", response_text).strip()
    start, end = cleaned.find('{'), cleaned.rfind('}')
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError: return None
    return None

def scan_repo_files(repo_path: str, include_yaml: bool, include_helm: bool,
                    max_file_bytes: int, max_files: int) -> List[Path]:
    repo = Path(repo_path)
    if not repo.is_dir():
        raise ValueError(f"Repository path '{repo_path}' is not a directory")
    allowed_exts = set(CODE_EXTS)
    if include_yaml: allowed_exts |= YAML_EXTS
    if include_helm: allowed_exts |= HELM_EXTS
    results: List[Path] = []
    for file_path in repo.rglob("*"):
        if len(results) >= max_files: break
        if not file_path.is_file(): continue
        if any(skip in file_path.parts for skip in SKIP_DIRS): continue
        if file_path.suffix.lower() not in allowed_exts: continue
        try:
            if file_path.stat().st_size > max_file_bytes: continue
        except OSError: continue
        results.append(file_path)
    return sorted(results, key=lambda p: (p.suffix, p.name.lower()))

# ---------- Core Analyzer ----------
class SmartAnalyzer:
    def __init__(self, console: Console, client: anthropic.Anthropic, cache: CacheManager):
        self.console = console
        self.client = client
        self.cache = cache

    def _call_claude(self, stage: str, file: Optional[str], prompt: str, max_tokens: int = 4000) -> Optional[str]:
        cached = self.cache.get(stage, file, prompt)
        if cached:
            self.console.print(f"[dim]Cache hit for {stage} ({file or 'n/a'})[/dim]")
            return cached.raw_response
        try:
            response = self.client.messages.create(
                model=CLAUDE_MODEL, max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text if response.content else ""
            parsed = parse_json_response(raw)
            self.cache.save(stage, file, prompt, raw, parsed)
            return raw
        except Exception as e:
            self.console.print(f"[red]API Error: {e}[/red]")
            return None

    def run_prioritization_stage(self, all_files: List[Path], question: str, debug: bool, limit: int) -> Optional[List[Dict[str, str]]]:
        self.console.print("[bold]Stage 1: Prioritization[/bold]")
        if not all_files: return None
        prompt = PromptFactory.prioritization(all_files, question, limit)
        raw = self._call_claude("prioritization", None, prompt)
        if not raw: return None
        if debug: self.console.print(Panel(raw, title="RAW API RESPONSE (Prioritization)"))
        parsed = parse_json_response(raw)
        if parsed and isinstance(parsed.get("prioritized_files"), list):
            prioritized_info = parsed["prioritized_files"]
            self.console.print(f"[green]✓ AI has suggested {len(prioritized_info)} files for analysis.[/green]\n")
            return prioritized_info
        self.console.print("[yellow]Could not parse prioritization response. Continuing with all files.[/yellow]")
        return None

    def run_deep_dive_stage(self, files: List[Path], question: str, verbose: bool, debug: bool, threshold: Optional[str]) -> List[Finding]:
        self.console.print("\n[bold]Stage 2: Deep Dive[/bold]")
        findings: List[Finding] = []
        for i, file_path in enumerate(files, 1):
            self.console.print(f"[[bold]{i}/{len(files)}[/bold]] Analyzing {file_path.name}...")
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                self.console.print(f"  [red]Error reading {file_path}: {e}[/red]"); continue

            if file_path.suffix.lower() in YAML_EXTS: prompt = PromptFactory.deep_dive_yaml(file_path, content, question)
            elif file_path.suffix.lower() in HELM_EXTS or "templates" in file_path.parts: prompt = PromptFactory.deep_dive_helm(file_path, content, question)
            else: prompt = PromptFactory.deep_dive(file_path, content, question)

            raw = self._call_claude("deep_dive", str(file_path), prompt)
            if not raw: continue
            if debug: self.console.print(Panel(raw, title=f"RAW API RESPONSE ({file_path.name})"))
            
            parsed = parse_json_response(raw)
            if parsed and isinstance(parsed.get("insights"), list):
                relevance = str(parsed.get("relevance", "N/A"))
                if threshold and relevance not in ("HIGH", threshold): continue
                
                file_insights: Sequence[dict] = parsed["insights"]
                self.console.print(f"   Relevance: {relevance}, Found: {len(file_insights)} insights")
                for ins in file_insights:
                    findings.append(Finding.from_dict(ins, str(file_path), relevance))
                    if verbose:
                        self.console.print(f"     [yellow]Finding:[/] {ins.get('finding')} (Impact: {ins.get('impact')})")
            time.sleep(1)
        self.console.print(f"\n[green]✓ Deep dive complete. Found {len(findings)} total insights.[/green]")
        return findings

    def run_synthesis_stage(self, findings: List[Finding], question: str) -> str:
        self.console.print("\n[bold]Stage 3: Synthesis[/bold]")
        if not findings: return "No insights were found to synthesize."
        prompt = PromptFactory.synthesis(findings, question)
        raw = self._call_claude("synthesis", None, prompt)
        self.console.print("[green]✓ Synthesis complete.[/green]\n")
        return raw or "Synthesis failed."

    def run_payload_generation_stage(self, top_findings: List[Finding], debug: bool) -> None:
        self.console.print("\n[bold]Stage 4: Payload Generation[/bold]")
        for f in top_findings:
            try: snippet = Path(f.file_path).read_text(encoding="utf-8", errors="ignore")
            except Exception: snippet = "Could not read snippet."
            prompt = PromptFactory.payload_generation(f, snippet[:500])
            raw = self._call_claude("payload", f.file_path, prompt)
            if not raw: continue
            if debug: self.console.print(Panel(raw, title=f"RAW API RESPONSE (Payloads for {Path(f.file_path).name})"))
            parsed = parse_json_response(raw)
            if parsed:
                rt, bt = parsed.get("red_team_payload", {}), parsed.get("blue_team_payload", {})
                self.console.print(Panel(
                    f"[bold red]Red Team[/bold red]\nPayload: `{rt.get('payload','')}`\n{rt.get('explanation','')}\n\n"
                    f"[bold green]Blue Team[/bold green]\nPayload: `{bt.get('payload','')}`\n{bt.get('explanation','')}",
                    title=f"Payloads for '{f.finding}'", border_style="magenta"
                ))
            time.sleep(1)

# ---------- Output ----------
class OutputManager:
    def __init__(self, console: Console):
        self.console = console

    def display_console_summary(self, report: AnalysisReport) -> None:
        self.console.print(Panel(Markdown(report.synthesis),
                                 title="[bold blue]Analysis Report & Strategic Plan[/bold blue]",
                                 border_style="blue", expand=False))

    def save_reports(self, report: AnalysisReport, formats: List[str], output_base: Optional[str]) -> None:
        # UPDATED: Changed to timezone.utc for compatibility
        base = Path(output_base or f"analysis_{Path(report.repo_path).name}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}")
        for fmt in formats:
            if fmt == "console": continue
            out = base.with_suffix(f".{fmt}")
            try:
                if fmt == "markdown": content = f"# Analysis for `{report.repo_path}`\n\n## Question: {report.question}\n\n---\n\n{report.synthesis}"
                elif fmt == "html":
                    md_html = Markdown(report.synthesis)._render_str(self.console) # Basic conversion
                    content = f"<!doctype html><html><head><meta charset='utf-8'><title>Analysis Report</title><style>body{{font-family:sans-serif;max-width:800px;margin:2em auto;}}pre{{background:#f4f4f4;padding:1em;}}</style></head><body><h1>Analysis for <code>{report.repo_path}</code></h1><h2>Question: {report.question}</h2><hr/>{md_html}</body></html>"
                elif fmt == "json": content = json.dumps([asdict(f) for f in report.insights], indent=2)
                else: content = ""
                out.write_text(content, encoding="utf-8")
                self.console.print(f"[green]✓ Saved report to {out}[/green]")
            except Exception as e:
                self.console.print(f"[red]Error saving {fmt} report: {e}[/red]")

# ---------- Interactivity ----------
def clarify_question_interactively(question: str, console: Console) -> str:
    """If a question is broad, ask the user to clarify their goal."""
    if "security" in question.lower():
        console.print("\n[bold cyan]?[/] Your question is about [bold]security[/bold]. To focus the analysis, what aspect are you most interested in?")
        options = ["Injection Vulnerabilities (SQLi, XSS)", "Authentication & Authorization", "Insecure Data Handling (Secrets, PII)", "Dependency & Configuration Issues"]
        for i, opt in enumerate(options, 1): console.print(f"  ({i}) {opt}")
        choice = input("Enter number (or press Enter to skip): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            clarification = options[int(choice) - 1]
            console.print(f"[dim]Focusing on: {clarification}[/dim]")
            return f"{question}, focusing specifically on {clarification}."
    return question

# ---------- CLI & Main ----------
def create_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Smart Code Analyzer with caching + full features")
    p.add_argument("repo_path", help="Path to the repository to analyze")
    p.add_argument("question", nargs="?", help="Analysis question")
    p.add_argument("--cache-dir", default=".gowasp_cache", help="Directory for conversation cache")
    p.add_argument("--no-cache", action="store_true", help="Disable cache (always hit API)")
    p.add_argument("--save-conversations", action="store_true", help="Save full session log as JSON")
    p.add_argument("--include-yaml", action="store_true", help="Include .yaml/.yml files")
    p.add_argument("--include-helm", action="store_true", help="Include Helm templates")
    p.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    p.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    p.add_argument("--prioritize-top", type=int, default=15, help="Ask AI to prioritize top N files.")
    p.add_argument("--format", nargs="*", default=["console"], choices=["console", "html", "markdown", "json"])
    p.add_argument("--output", "-o", help="Base output filename")
    p.add_argument("--top-n", type=int, default=5, help="Number of items for payload generation")
    p.add_argument("--threshold", choices=["HIGH", "MEDIUM"], help="Filter findings below this relevance")
    p.add_argument("--generate-payloads", action="store_true", help="Generate Red/Blue payloads")
    p.add_argument("-v", "--verbose", action="store_true", help="Print findings inline")
    p.add_argument("--debug", action="store_true", help="Print raw API responses")
    return p

def main() -> None:
    args = create_parser().parse_args()
    console = Console()

    api_key = get_api_key()
    client = anthropic.Anthropic(api_key=api_key)
    cache = CacheManager(args.cache_dir, use_cache=not args.no_cache)
    analyzer = SmartAnalyzer(console, client, cache)

    repo_path = Path(args.repo_path)
    if not repo_path.exists():
        console.print(f"[red]Error: Repository path '{repo_path}' does not exist[/red]"); sys.exit(1)

    question = args.question or input("Enter analysis question: ").strip()
    if not question: console.print("[red]No question provided[/red]"); sys.exit(1)
    
    question = clarify_question_interactively(question, console)

    files = scan_repo_files(repo_path, args.include_yaml, args.include_helm, args.max_file_bytes, args.max_files)
    console.print(f"\nFound [bold]{len(files)}[/bold] files to analyze.")

    prioritized_info = analyzer.run_prioritization_stage(files, question, args.debug, args.prioritize_top)
    
    files_to_analyze = files
    if prioritized_info:
        table = Table(title="AI-Prioritized Files for Analysis")
        table.add_column("File Name", style="cyan")
        table.add_column("Reason for Selection", style="magenta")
        for item in prioritized_info:
            table.add_row(item.get('file_name', 'N/A'), item.get('reason', 'N/A'))
        console.print(table)
        
        while True:
            prompt = f"[?] Proceed with all {len(prioritized_info)} files? ([Y]es / [N]o / Enter a number to analyze less): "
            choice = input(prompt).strip().lower()
            
            if choice in ('y', 'yes', ''):
                break
            elif choice in ('n', 'no'):
                console.print("[yellow]Analysis aborted by user.[/yellow]"); sys.exit(0)
            elif choice.isdigit():
                num_to_analyze = int(choice)
                if 0 < num_to_analyze <= len(prioritized_info):
                    prioritized_info = prioritized_info[:num_to_analyze]
                    console.print(f"[dim]Proceeding with the top {num_to_analyze} file(s).[/dim]")
                    break
                else:
                    console.print(f"[red]Please enter a number between 1 and {len(prioritized_info)}.[/red]")
            else:
                console.print("[red]Invalid input. Please enter 'y', 'n', or a number.[/red]")

        prioritized_filenames = {item['file_name'] for item in prioritized_info if 'file_name' in item}
        files_to_analyze = [p for p in files if p.name in prioritized_filenames]

    findings = analyzer.run_deep_dive_stage(files_to_analyze, question, args.verbose, args.debug, args.threshold)
    synthesis = analyzer.run_synthesis_stage(findings, question)

    report = AnalysisReport(
        # UPDATED: Changed to timezone.utc for compatibility
        repo_path=str(repo_path), question=question,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        file_count=len(files_to_analyze), insights=findings, synthesis=synthesis,
    )

    out = OutputManager(console)
    if "console" in args.format: out.display_console_summary(report)
    
    file_formats = [f for f in args.format if f != "console"]
    if file_formats: out.save_reports(report, file_formats, args.output)

    if args.generate_payloads and findings:
        analyzer.run_payload_generation_stage(findings[:args.top_n], args.debug)

    if args.save_conversations: cache.save_session_log()

if __name__ == "__main__":
    main()
