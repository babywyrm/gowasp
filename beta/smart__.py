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
from typing import List, Dict, Optional, Any, TypeAlias
from dataclasses import dataclass
from datetime import datetime

import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

# --- Constants & Type Aliases ---
SUPPORTED_EXTENSIONS = {'.py', '.go', '.java', '.js', '.ts', '.php', '.rb', '.jsx', '.tsx'}
CLAUDE_MODEL = "claude-3-5-sonnet-20241022"
FindingDict: TypeAlias = Dict[str, Any]

# --- Data Structures ---
@dataclass
class Finding:
    """Represents a single, actionable finding within a file."""
    file_path: str
    finding: str
    recommendation: str
    relevance: str
    line_number: Optional[int] = None

    @classmethod
    def from_dict(cls, insight_dict: FindingDict, file_path: str, relevance: str) -> 'Finding':
        """Safely creates a Finding instance from a raw dictionary."""
        return cls(
            file_path=file_path,
            relevance=relevance,
            finding=insight_dict.get('finding', 'N/A'),
            recommendation=insight_dict.get('recommendation', 'N/A'),
            line_number=insight_dict.get('line_number'),
        )

@dataclass
class AnalysisReport:
    """A structured container for the complete analysis results."""
    repo_path: str
    question: str
    timestamp: str
    file_count: int
    insights: List[Finding]
    synthesis: str

# --- Helper Functions ---
def get_api_key() -> str:
    """Retrieves the Claude API key from an environment variable."""
    api_key = os.getenv('CLAUDE_API_KEY')
    if not api_key:
        print("Error: CLAUDE_API_KEY environment variable not set.")
        sys.exit(1)
    return api_key

def parse_json_response(response_text: str) -> Optional[Dict]:
    """Safely parses a JSON object from the API's potentially unstructured text."""
    try:
        match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
    except (json.JSONDecodeError):
        pass
    return None

def scan_repo_files(repo_path: str) -> List[Path]:
    """Scans a repository for supported file types."""
    repo = Path(repo_path)
    files = []
    skip_dirs = {'.git', 'node_modules', '__pycache__', 'vendor', 'build', 'dist'}
    for file_path in repo.rglob("*"):
        if (file_path.is_file() and file_path.suffix in SUPPORTED_EXTENSIONS and
            not any(skip in file_path.parts for skip in skip_dirs)):
            files.append(file_path)
    return sorted(files)

# --- Core Logic Classes ---
class PromptFactory:
    """Generates dynamic prompts for each stage of the analysis."""

    @staticmethod
    def prioritization(all_files: List[Path], question: str) -> str:
        """Creates the prompt for the file prioritization stage."""
        filenames = [f.name for f in all_files]
        return f"""You are a lead software architect. Based on the user's question, identify the most critical files to analyze from the list below.

User Question: "{question}"

File List:
{json.dumps(filenames, indent=2)}

Return a JSON object with a single key "prioritized_files" containing a list of the top 15 most relevant filenames. Your response must contain ONLY the JSON object.
Example: {{"prioritized_files": ["Login.java", "UserService.java", "ApiAction.java"]}}"""

    @staticmethod
    def deep_dive(file_path: Path, content: str, question: str) -> str:
        """Creates the prompt for the detailed file analysis stage."""
        return f"""You are an expert code analyst. Analyze the following code in the context of the user's question.
FILE: {file_path}
QUESTION: {question}

Provide a concise analysis in this exact JSON format. Your entire response must be ONLY the JSON object.
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

    @staticmethod
    def synthesis(all_findings: List[Finding], question: str) -> str:
        """Creates a dynamic synthesis prompt tailored to the user's question."""
        condensed_findings = [f"- {f.finding} (in {Path(f.file_path).name})" for f in all_findings]
        
        # Dynamically select the synthesis goal based on the question
        q_lower = question.lower()
        if any(kw in q_lower for kw in ["security", "vulnerability", "threat", "exploit"]):
            synthesis_goal = """
1.  **Executive Summary:** A brief, high-level overview of the codebase's security posture.
2.  **Top Threat Vectors:** Identify the 3-5 most critical, overarching vulnerability patterns.
3.  **Strategic Remediation Plan:** Provide a prioritized, actionable plan to address these key patterns."""
        elif any(kw in q_lower for kw in ["performance", "speed", "latency", "bottleneck"]):
            synthesis_goal = """
1.  **Performance Profile:** A brief, high-level overview of the codebase's likely performance characteristics.
2.  **Key Bottlenecks:** Identify the 3-5 most critical, overarching performance anti-patterns.
3.  **Optimization Strategy:** Provide a prioritized, actionable plan to address these key bottlenecks."""
        else: # Default for general, refactoring, or other questions
            synthesis_goal = """
1.  **Architectural Overview:** A brief, high-level summary of the codebase's design and quality.
2.  **Key Code Smells / Patterns:** Identify the 3-5 most critical, overarching design or maintenance issues.
3.  **Strategic Refactoring Plan:** Provide a prioritized, actionable plan to improve the codebase's structure and maintainability."""

        return f"""You are a principal software architect providing an executive summary. Based on the user's original question and the list of raw findings from a codebase scan, generate a high-level report.

Original Question: "{question}"

Raw Findings:
{chr(10).join(condensed_findings)}

Your task is to synthesize these findings. Structure your response in Markdown with the following sections:
{synthesis_goal}"""

class SmartAnalyzer:
    """Orchestrates the multi-stage code analysis process."""
    def __init__(self, console: Console, client: anthropic.Anthropic):
        self.console = console
        self.client = client

    def _call_claude(self, prompt: str, max_tokens: int = 4000) -> Optional[str]:
        """A centralized method for making calls to the Claude API."""
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
        """Stage 1: Asks the AI to prioritize which files are most relevant."""
        self.console.print("[bold]Stage 1: Prioritizing files...[/bold]")
        prompt = PromptFactory.prioritization(all_files, question)
        response_text = self._call_claude(prompt)
        if not response_text: return all_files

        if debug: self.console.print(Panel(response_text, title="[bold blue]RAW API RESPONSE (Prioritization)[/bold blue]"))

        parsed = parse_json_response(response_text)
        if parsed and "prioritized_files" in parsed and isinstance(parsed["prioritized_files"], list):
            prioritized_names = set(parsed["prioritized_files"])
            prioritized_files = [p for p in all_files if p.name in prioritized_names]
            self.console.print(f"[green]✓ Prioritized {len(prioritized_files)} files for deep analysis.[/green]\n")
            return prioritized_files

        self.console.print("[yellow]Could not determine priority, analyzing all files.[/yellow]\n")
        return all_files

    def run_deep_dive_stage(self, files_to_analyze: List[Path], question: str, verbose: bool, debug: bool) -> List[Finding]:
        """Stage 2: Performs a detailed, file-by-file analysis."""
        self.console.print("[bold]Stage 2: Performing deep dive analysis...[/bold]")
        all_findings: List[Finding] = []

        for i, file_path in enumerate(files_to_analyze, 1):
            self.console.print(f"[[bold]{i}/{len(files_to_analyze)}[/bold]] Analyzing [cyan]{file_path.name}[/cyan]...")
            try:
                content = file_path.read_text(encoding='utf-8', errors='replace')
            except IOError as e:
                self.console.print(f"   [red]Error reading file {file_path.name}: {e}[/red]")
                continue

            prompt = PromptFactory.deep_dive(file_path, content, question)
            response_text = self._call_claude(prompt)
            if not response_text: continue

            if debug: self.console.print(Panel(response_text, title=f"[bold blue]RAW API RESPONSE ({file_path.name})[/bold blue]"))

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
        """Stage 3: Asks the AI to synthesize all findings into a high-level summary."""
        self.console.print("[bold]Stage 3: Synthesizing results into a final report...[/bold]")
        if not all_findings:
            return "No insights were found, so no synthesis could be performed."

        prompt = PromptFactory.synthesis(all_findings, question)
        response_text = self._call_claude(prompt)
        self.console.print("[green]✓ Synthesis complete.[/green]\n")
        return response_text or "Failed to generate a synthesis report."

class OutputManager:
    """Handles the display and saving of the final analysis report."""
    def __init__(self, console: Console):
        self.console = console

    def display_console_summary(self, report: AnalysisReport, top_n: int) -> None:
        """Prints a final, formatted summary of the analysis to the console."""
        self.console.print(Panel(Markdown(report.synthesis), title="[bold blue]AI-Generated Synthesis[/bold blue]", border_style="blue"))
        
        if not report.insights: return

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
        """Saves the analysis report to files in the specified formats."""
        if not output_base:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            repo_name = Path(report.repo_path).name
            base_path = Path(f"analysis_{repo_name}_{timestamp}")
        else:
            base_path = Path(output_base).with_suffix('')

        for fmt in formats:
            if fmt == 'console': continue
            output_path = base_path.with_suffix(f".{fmt}")
            try:
                content = ""
                if fmt == 'markdown': content = f"# Analysis for {report.repo_path}\n\n## Question: {report.question}\n\n{report.synthesis}"
                elif fmt == 'html': content = Markdown(content).html
                
                output_path.write_text(content, encoding='utf-8')
                self.console.print(f"[bold green]✓ Report saved to: {output_path}[/bold green]")
            except Exception as e:
                self.console.print(f"[red]Error saving {fmt} report: {e}[/red]")

def create_parser() -> argparse.ArgumentParser:
    """Creates and configures the command-line argument parser."""
    examples = """
Examples:
  # Interactive security scan
  python smart_analyzer.py /path/to/repo

  # Performance analysis with verbose output
  python smart_analyzer.py /path/to/repo "Find performance bottlenecks" -v

  # Generate HTML and Markdown reports for a refactoring analysis
  python smart_analyzer.py /path/to/repo "Suggest refactoring improvements" --format html markdown --output refactor_plan

  # Debug the API calls for a specific question
  python smart_analyzer.py /path/to/repo "Find hardcoded secrets" --debug
    """
    parser = argparse.ArgumentParser(description="A multi-stage AI code analyzer.", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=examples)
    parser.add_argument('repo_path', help='Path to the repository to analyze')
    parser.add_argument('question', nargs='?', help='Analysis question (prompts if not provided)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print detailed insights for each file as they are found.')
    parser.add_argument('--debug', action='store_true', help='Print raw API responses for every call.')
    parser.add_argument('--format', nargs='*', default=['console'], choices=['console', 'html', 'markdown'], help='One or more output formats.')
    parser.add_argument('-o', '--output', help='Base output file path (e.g., "report"). Suffix is ignored.')
    parser.add_argument('--no-color', action='store_true', help='Disable colorized output.')
    parser.add_argument('--top-n', type=int, default=5, help='Number of items for summary tables.')
    return parser

def get_question_interactively(console: Console) -> str:
    """Prompts the user to enter an analysis question."""
    console.print("\n[bold cyan]What would you like to analyze about this codebase?[/bold cyan]")
    console.print("[dim]Examples: 'Find security vulnerabilities', 'Suggest performance improvements', 'How can I refactor this code?'[/dim]")
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
    
    try:
        api_key = get_api_key()
        client = anthropic.Anthropic(api_key=api_key)
        
        if not os.path.exists(args.repo_path):
            console.print(f"[red]Error: Repository path '{args.repo_path}' does not exist[/red]")
            sys.exit(1)
        
        question = args.question or get_question_interactively(console)
        
        console.print(Panel(f"[bold]Repository:[/bold] {args.repo_path}\n[bold]Question:[/bold] {question}", title="[bold blue]Dynamic Code Analyzer[/bold blue]"))
        
        all_files = scan_repo_files(args.repo_path)
        console.print(f"Found {len(all_files)} total code files.\n")
        
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

    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Analysis interrupted by user.[/bold yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
