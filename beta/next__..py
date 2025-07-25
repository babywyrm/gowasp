#!/usr/bin/env python3
"""
A multi-stage, 'lite' dynamic code analyzer that uses a Prioritize-Analyze-Synthesize
pipeline to provide holistic insights into a codebase.

Requires the 'rich' and 'anthropic' libraries:
pip install rich anthropic
"""

import os
import re
import sys
import json
import time
import argparse
from pathlib import Path
from collections import Counter
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime

import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

# --- Constants ---
SUPPORTED_EXTENSIONS = {
    '.py', '.go', '.java', '.js', '.ts', '.php', '.rb', '.jsx', '.tsx'
}
CLAUDE_MODEL = "claude-3-5-sonnet-20241022"


# --- Data Structures ---
@dataclass
class Finding:
    """Represents a single, actionable finding within a file."""
    file_path: str
    finding: str
    recommendation: str
    relevance: str
    line_number: Optional[int] = None


@dataclass
class AnalysisReport:
    """A structured container for the complete analysis results."""
    repo_path: str
    question: str
    timestamp: str
    file_count: int
    insights: List[Finding]
    synthesis: str


# --- Core Logic ---
def get_api_key() -> str:
    """Retrieves the Claude API key from an environment variable."""
    api_key = os.getenv('CLAUDE_API_KEY')
    if not api_key:
        print("Error: CLAUDE_API_KEY environment variable not set.")
        sys.exit(1)
    return api_key


def parse_json_response(response_text: str) -> Optional[Dict]:
    """
    Safely parses a JSON object from the API's potentially unstructured text
    by finding the first '{' and last '}'.
    """
    try:
        start_index = response_text.find('{')
        end_index = response_text.rfind('}')
        if start_index != -1 and end_index != -1 and end_index > start_index:
            json_str = response_text[start_index : end_index + 1]
            return json.loads(json_str)
    except (json.JSONDecodeError, IndexError):
        pass
    return None


def scan_repo_files(repo_path: str) -> List[Path]:
    """Scans a repository for supported file types, skipping common vendor directories."""
    repo = Path(repo_path)
    files = []
    skip_dirs = {'.git', 'node_modules', '__pycache__', 'vendor', 'build', 'dist'}
    for file_path in repo.rglob("*"):
        if (
            file_path.is_file()
            and file_path.suffix in SUPPORTED_EXTENSIONS
            and not any(skip in file_path.parts for skip in skip_dirs)
        ):
            files.append(file_path)
    return sorted(files)


class SmartAnalyzer:
    """Orchestrates the multi-stage code analysis process."""

    def __init__(self, console: Console, client: anthropic.Anthropic):
        self.console = console
        self.client = client

    def _call_claude(self, prompt: str, max_tokens: int = 4000) -> Optional[str]:
        """A centralized method for making calls to the Claude API."""
        try:
            response = self.client.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text
        except Exception as e:
            self.console.print(f"[red]API Error: {e}[/red]")
            return None

    def run_prioritization_stage(
        self, all_files: List[Path], question: str, debug: bool
    ) -> List[Path]:
        """Stage 1: Asks the AI to prioritize which files are most relevant."""
        self.console.print("[bold]Stage 1: Prioritizing files...[/bold]")
        filenames = [f.name for f in all_files]

        prompt = f"""You are a lead software architect. Based on the user's question, identify the most critical files to analyze from the list below.

User Question: "{question}"

File List:
{json.dumps(filenames, indent=2)}

Return a JSON object with a single key "prioritized_files" containing a list of the top 15 most relevant filenames. Your response must contain ONLY the JSON object, with no surrounding text or explanation.
Example: {{"prioritized_files": ["Login.java", "UserService.java", "ApiAction.java"]}}"""

        response_text = self._call_claude(prompt)
        if not response_text:
            return all_files

        if debug:
            self.console.print(
                Panel(
                    response_text,
                    title="[bold blue]RAW API RESPONSE (Prioritization)[/bold blue]",
                    border_style="blue",
                )
            )

        parsed = parse_json_response(response_text)
        if (
            parsed
            and "prioritized_files" in parsed
            and isinstance(parsed["prioritized_files"], list)
        ):
            prioritized_names = set(parsed["prioritized_files"])
            prioritized_files = [p for p in all_files if p.name in prioritized_names]
            self.console.print(
                f"[green]✓ Prioritized {len(prioritized_files)} files for deep analysis.[/green]\n"
            )
            return prioritized_files

        self.console.print(
            "[yellow]Could not determine priority, analyzing all files.[/yellow]\n"
        )
        return all_files

    def run_deep_dive_stage(
        self, files_to_analyze: List[Path], question: str, verbose: bool, debug: bool
    ) -> List[Finding]:
        """Stage 2: Performs a detailed, file-by-file analysis on the prioritized files."""
        self.console.print("[bold]Stage 2: Performing deep dive analysis...[/bold]")
        all_findings: List[Finding] = []

        for i, file_path in enumerate(files_to_analyze, 1):
            self.console.print(
                f"[[bold]{i}/{len(files_to_analyze)}[/bold]] Analyzing [cyan]{file_path.name}[/cyan]..."
            )

            try:
                content = file_path.read_text(encoding='utf-8', errors='replace')
            except (IOError, PermissionError) as e:
                self.console.print(
                    f"   [red]Error reading file {file_path.name}: {e}[/red]"
                )
                continue

            prompt = f"""You are an expert code analyst. Analyze the following code in the context of the user's question.
FILE: {file_path}
QUESTION: {question}

Provide a concise analysis in this exact JSON format. Your entire response must be ONLY the JSON object, without any introductory text, comments, or explanations.
{{
  "relevance": "HIGH|MEDIUM|LOW|NONE",
  "insights": [
    {{
      "finding": "Description of the finding.",
      "line_number": 45,
      "recommendation": "Specific, actionable recommendation."
    }}
  ]
}}
CODE TO ANALYZE:
{content}"""

            response_text = self._call_claude(prompt)
            if not response_text:
                continue

            if debug:
                self.console.print(
                    Panel(
                        response_text,
                        title=f"[bold blue]RAW API RESPONSE ({file_path.name})[/bold blue]",
                        border_style="blue",
                    )
                )

            parsed = parse_json_response(response_text)
            if parsed and 'insights' in parsed:
                relevance = parsed.get('relevance', 'N/A')
                file_insights = parsed.get('insights', [])
                self.console.print(
                    f"   Relevance: [bold yellow]{relevance}[/bold yellow], Found [bold]{len(file_insights)}[/bold] insights."
                )

                if verbose and file_insights:
                    for insight in file_insights:
                        self.console.print(
                            f"     [bold]Finding:[/bold] {insight.get('finding', 'N/A')} (Line: {insight.get('line_number', 'N/A')})"
                        )
                        self.console.print(
                            f"     [bold]Recommendation:[/bold] {insight.get('recommendation', 'N/A')}\n"
                        )

                for insight in file_insights:
                    all_findings.append(
                        Finding(
                            file_path=str(file_path),
                            relevance=relevance,
                            finding=insight.get('finding', 'N/A'),
                            recommendation=insight.get('recommendation', 'N/A'),
                            line_number=insight.get('line_number'),
                        )
                    )
            else:
                self.console.print(
                    "   [yellow]Could not parse a structured response from API.[/yellow]"
                )

            time.sleep(1)

        self.console.print("[green]✓ Deep dive analysis complete.[/green]\n")
        return all_findings

    def run_synthesis_stage(
        self, all_findings: List[Finding], question: str
    ) -> str:
        """Stage 3: Asks the AI to synthesize all findings into a high-level summary."""
        self.console.print(
            "[bold]Stage 3: Synthesizing results into a final report...[/bold]"
        )
        if not all_findings:
            return "No insights were found, so no synthesis could be performed."

        condensed_findings = [
            f"- {f.finding} (in {Path(f.file_path).name})" for f in all_findings
        ]

        prompt = f"""You are a principal software architect providing an executive summary. Based on the user's original question and the list of raw findings from a codebase scan, generate a high-level report.

Original Question: "{question}"

Raw Findings:
{chr(10).join(condensed_findings)}

Your task is to synthesize these findings. Structure your response in Markdown with the following sections:
1.  **Executive Summary:** A brief, high-level overview of the codebase's state regarding the user's question.
2.  **Top Threat Vectors / Key Patterns:** Identify the 3-5 most critical, overarching patterns or threat vectors discovered.
3.  **Strategic Recommendations:** Provide a prioritized, actionable plan to address these key patterns.
"""

        response_text = self._call_claude(prompt)
        self.console.print("[green]✓ Synthesis complete.[/green]\n")
        return response_text or "Failed to generate a synthesis report."


def display_console_summary(
    console: Console, report: AnalysisReport, top_n: int
) -> None:
    """Prints a final, formatted summary of the analysis to the console."""
    console.print(
        Panel(
            Markdown(report.synthesis),
            title="[bold blue]Executive Summary & Threat Model[/bold blue]",
            border_style="blue",
        )
    )

    if not report.insights:
        return

    recommendations_table = Table(
        title=f"[bold yellow]Top {top_n} Key Recommendations[/bold yellow]"
    )
    recommendations_table.add_column("Recommendation", style="cyan")
    recommendations_table.add_column("File", style="magenta")
    for insight in report.insights[:top_n]:
        recommendations_table.add_row(
            insight.recommendation, Path(insight.file_path).name
        )

    file_counts = Counter(i.file_path for i in report.insights)
    vulnerable_files_table = Table(
        title=f"[bold red]Top {top_n} Most Impacted Files[/bold red]"
    )
    vulnerable_files_table.add_column("File", style="magenta")
    vulnerable_files_table.add_column("Findings Count", style="red", justify="right")
    for file_path, count in file_counts.most_common(top_n):
        vulnerable_files_table.add_row(Path(file_path).name, str(count))

    console.print(
        f"\nAnalyzed [bold]{report.file_count}[/bold] files and found [bold]{len(report.insights)}[/bold] total insights.\n"
    )
    console.print(recommendations_table)
    console.print(vulnerable_files_table)


def create_parser() -> argparse.ArgumentParser:
    """Creates and configures the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="A multi-stage 'lite' dynamic code analyzer using Claude."
    )
    parser.add_argument('repo_path', help='Path to the repository to analyze')
    parser.add_argument(
        'question', nargs='?', help='Analysis question (will prompt if not provided)'
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Print detailed insights for each file as they are found.',
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Print raw API responses for every call, regardless of parsing success.',
    )
    parser.add_argument(
        '--format',
        nargs='*',
        default=['console'],
        choices=['console', 'html', 'markdown'],
        help='One or more output formats.',
    )
    parser.add_argument(
        '--output',
        '-o',
        help='Base output file path (e.g., "report"). Suffix is ignored.',
    )
    parser.add_argument(
        '--no-color', action='store_true', help='Disable colorized output in the terminal.'
    )
    parser.add_argument(
        '--top-n',
        type=int,
        default=5,
        help='Number of items to show in summary tables.',
    )
    return parser


def get_question_interactively(console: Console) -> str:
    """Prompts the user to enter an analysis question."""
    console.print("\n[bold cyan]What would you like to analyze about this codebase?[/bold cyan]")
    question = input("Enter your question: ").strip()
    if not question:
        console.print("[red]No question provided. Exiting.[/red]")
        sys.exit(1)
    return question


def main() -> None:
    """Main execution function that orchestrates the analysis process."""
    parser = create_parser()
    args = parser.parse_args()

    console = Console(no_color=args.no_color)

    api_key = get_api_key()
    client = anthropic.Anthropic(api_key=api_key)

    if not os.path.exists(args.repo_path):
        console.print(f"[red]Error: Repository path '{args.repo_path}' does not exist[/red]")
        sys.exit(1)

    question = args.question or get_question_interactively(console)

    console.print(
        Panel(
            f"[bold]Repository:[/bold] {args.repo_path}\n[bold]Question:[/bold] {question}",
            title="[bold blue]Dynamic Code Analyzer[/bold blue]",
        )
    )

    all_files = scan_repo_files(args.repo_path)
    console.print(f"Found {len(all_files)} total code files.\n")

    analyzer = SmartAnalyzer(console, client)

    prioritized_files = analyzer.run_prioritization_stage(
        all_files, question, args.debug
    )
    all_insights = analyzer.run_deep_dive_stage(
        prioritized_files, question, args.verbose, args.debug
    )
    synthesis_text = analyzer.run_synthesis_stage(all_insights, question)

    report = AnalysisReport(
        repo_path=args.repo_path,
        question=question,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        file_count=len(prioritized_files),
        insights=all_insights,
        synthesis=synthesis_text,
    )

    if 'console' in args.format:
        display_console_summary(console, report, args.top_n)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user.")
        sys.exit(1)
