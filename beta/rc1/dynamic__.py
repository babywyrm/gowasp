#!/usr/bin/env python3
"""
A 'lite' dynamic code analyzer that scans a repository, sends individual files
to the Claude API for analysis against a user-provided question, and summarizes
the findings with proper attribution and multiple report formats.

Requires the 'rich' and 'anthropic' libraries:
pip install rich anthropic
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path
from collections import Counter
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Defines which file extensions are eligible for analysis.
SUPPORTED_EXTENSIONS = {'.py', '.go', '.java', '.js', '.ts', '.php', '.rb', '.jsx', '.tsx'}

# --- Data Structures ---
@dataclass
class AnalysisReport:
    """A structured container for the complete analysis results."""
    repo_path: str
    question: str
    timestamp: str
    file_count: int
    insights: List[Dict]

# --- Core Logic Classes ---
class OutputFormatter:
    """Provides static methods for formatting the final report into different file types."""
    
    @staticmethod
    def format_markdown(report: AnalysisReport) -> str:
        """Formats the report as a Markdown document."""
        md_lines = [
            f"# Code Analysis Report\n",
            f"**Repository:** `{report.repo_path}`  ",
            f"**Question:** {report.question}  ",
            f"**Analysis Date:** {report.timestamp}\n",
            f"Analyzed **{report.file_count}** files and found **{len(report.insights)}** total insights.\n",
            "---\n",
            "## Top 5 Key Recommendations\n"
        ]
        
        for insight in report.insights[:5]:
            md_lines.append(f"- **{Path(insight.get('file_path', 'Unknown')).name}**: {insight.get('recommendation', 'N/A')}")
        
        md_lines.append("\n## Most Vulnerable Files\n")
        file_counts = Counter(i['file_path'] for i in report.insights if 'file_path' in i)
        for file_path, count in file_counts.most_common(5):
            md_lines.append(f"- **{Path(file_path).name}**: {count} findings")
            
        return "\n".join(md_lines)

    @staticmethod
    def format_html(report: AnalysisReport) -> str:
        """Formats the report as a self-contained HTML document."""
        top_recs_html = "".join([f"<li><strong>{Path(i.get('file_path', 'Unknown')).name}</strong>: {i.get('recommendation', 'N/A')}</li>" for i in report.insights[:5]])
        
        file_counts = Counter(i['file_path'] for i in report.insights if 'file_path' in i)
        top_files_html = "".join([f"<li><strong>{Path(fp).name}</strong>: {count} findings</li>" for fp, count in file_counts.most_common(5)])

        return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Code Analysis Report</title><style>body{{font-family:sans-serif;line-height:1.6;margin:2em;background:#f8f9fa;}} .container{{max-width:800px;margin:auto;background:white;padding:2em;border-radius:8px;box-shadow:0 0 10px rgba(0,0,0,0.1);}} h1,h2{{color:#343a40;border-bottom:1px solid #dee2e6;padding-bottom:0.3em;}} code{{background:#e9ecef;padding:2px 4px;border-radius:3px;}}</style></head><body><div class="container"><h1>Code Analysis Report</h1><p><strong>Repository:</strong> <code>{report.repo_path}</code></p><p><strong>Question:</strong> {report.question}</p><p><strong>Timestamp:</strong> {report.timestamp}</p><h2>Summary</h2><p>Analyzed <strong>{report.file_count}</strong> files and found <strong>{len(report.insights)}</strong> total insights.</p><h2>Top 5 Key Recommendations</h2><ul>{top_recs_html}</ul><h2>Most Vulnerable Files</h2><ul>{top_files_html}</ul></div></body></html>"""

def get_api_key() -> str:
    """Retrieves the Claude API key from an environment variable."""
    api_key = os.getenv('CLAUDE_API_KEY')
    if not api_key:
        print("Error: CLAUDE_API_KEY environment variable not set.")
        sys.exit(1)
    return api_key

def get_dynamic_prompt(file_path: Path, code_content: str, question: str) -> str:
    """Creates the prompt for the Claude API, requesting a structured JSON response."""
    return f"""You are an expert code analyst. Analyze the following code in the context of the user's question.

FILE: {file_path}
QUESTION: {question}

Provide a concise analysis in this exact JSON format:
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
{code_content}"""

def analyze_file_with_claude(client: anthropic.Anthropic, file_path: Path, question: str, console: Console, *, model: str, max_tokens: int, temperature: float) -> Optional[str]:
    """Analyzes a single file using the Claude API."""
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        # Explicitly limit file size to prevent memory issues
        if not content.strip() or len(content) > 50000:
            return None
        content = content[:50000]  # Limit file size explicitly
        
        console.print(f"   [dim]File size: {len(content)} characters[/dim]")
        prompt = get_dynamic_prompt(file_path, content, question)
        
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
        )
        return response.content[0].text
    except Exception as e:
        console.print(f"   [red]Error analyzing {file_path.name}: {e}[/red]")
        return None

def parse_json_response(response_text: str) -> Optional[Dict[str, Any]]:
    """Safely parses a JSON object from the API's potentially unstructured text response."""
    try:
        start = response_text.find('{')
        end = response_text.rfind('}') + 1
        if start >= 0 and end > start:
            return json.loads(response_text[start:end])
    except json.JSONDecodeError:
        pass
    return None

def scan_repo_files(repo_path: str) -> List[Path]:
    """Scans a repository for supported file types."""
    repo = Path(repo_path)
    files = []
    skip_dirs = {'.git', 'node_modules', '__pycache__', 'vendor', 'build', 'dist'}
    for file_path in repo.rglob("*"):
        if (file_path.is_file() and 
            file_path.suffix in SUPPORTED_EXTENSIONS and 
            not any(skip in file_path.parts for skip in skip_dirs)):
            files.append(file_path)
    return sorted(files)

def get_question(args: argparse.Namespace, console: Console) -> str:
    """Gets the analysis question from arguments or prompts the user."""
    if args.question:
        return args.question
    
    console.print("\n[bold cyan]What would you like to analyze about this codebase?[/bold cyan]")
    question = input("Enter your question: ").strip()
    if not question:
        console.print("[red]No question provided. Exiting.[/red]")
        sys.exit(1)
    return question

def display_console_summary(console: Console, report: AnalysisReport) -> None:
    """Prints a final, formatted summary of the analysis to the console."""
    console.print(Panel("[bold green]Analysis Complete[/bold green]", border_style="green", expand=False))
    
    if not report.insights:
        console.print("\n[yellow]No specific insights were found for this question.[/yellow]")
        return

    recommendations_table = Table(title="[bold yellow]Top 5 Key Recommendations[/bold yellow]")
    recommendations_table.add_column("Recommendation", style="cyan")
    recommendations_table.add_column("File", style="magenta")
    for insight in report.insights[:5]:
        recommendations_table.add_row(insight.get('recommendation', 'N/A'), Path(insight.get('file_path', 'Unknown')).name)
    
    file_counts = Counter(i['file_path'] for i in report.insights if 'file_path' in i)
    vulnerable_files_table = Table(title="[bold red]Most Vulnerable Files[/bold red]")
    vulnerable_files_table.add_column("File", style="magenta")
    vulnerable_files_table.add_column("Findings Count", style="red", justify="right")
    for file_path, count in file_counts.most_common(5):
        vulnerable_files_table.add_row(Path(file_path).name, str(count))

    console.print(f"\nAnalyzed [bold]{report.file_count}[/bold] files and found [bold]{len(report.insights)}[/bold] total insights.\n")
    console.print(recommendations_table)
    console.print(vulnerable_files_table)

def save_reports(report: AnalysisReport, formats: List[str], output_base: Optional[str], console: Console) -> None:
    """Saves the analysis report to files in the specified formats."""
    if output_base:
        base_path = Path(output_base).with_suffix('')
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        repo_name = Path(report.repo_path).name
        base_path = Path(f"analysis_{repo_name}_{timestamp}")

    for fmt in formats:
        if fmt == 'console': continue
        output_path = base_path.with_suffix(f".{fmt}")
        try:
            content = ""
            if fmt == 'json': content = json.dumps([i for i in report.insights], indent=2)
            elif fmt == 'markdown': content = OutputFormatter.format_markdown(report)
            elif fmt == 'html': content = OutputFormatter.format_html(report)
            
            output_path.write_text(content, encoding='utf-8')
            console.print(f"[bold green]✓ Report saved to: {output_path}[/bold green]")
        except Exception as e:
            console.print(f"[red]Error saving {fmt} report: {e}[/red]")

def create_parser() -> argparse.ArgumentParser:
    """Creates and configures the command-line argument parser."""
    parser = argparse.ArgumentParser(description="A 'lite' dynamic code analyzer using Claude.")
    parser.add_argument('repo_path', help='Path to the repository to analyze')
    parser.add_argument('question', nargs='?', help='Analysis question (will prompt if not provided)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Print detailed insights for each file as they are found.')
    parser.add_argument('--format', nargs='*', default=['console'], choices=['console', 'html', 'markdown', 'json'], help='One or more output formats.')
    parser.add_argument('--output', '-o', help='Base output file path (e.g., "report"). Suffix is ignored.')
    parser.add_argument('--no-color', action='store_true', help='Disable colorized output in the terminal.')
    # Model and generation controls
    parser.add_argument('--model', default='claude-3-5-sonnet-20241022', help='Claude model to use')
    parser.add_argument('--max-tokens', type=int, default=4000, help='Max tokens per response')
    parser.add_argument('--temperature', type=float, default=0.0, help='Sampling temperature (0.0 for determinism)')
    # Scan filters
    parser.add_argument('--include-exts', nargs='*', help='Only include these extensions (e.g., .py .go)')
    parser.add_argument('--ignore-dirs', nargs='*', help='Additional directories to skip')
    return parser

def main() -> None:
    """Main execution function that orchestrates the analysis process."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Initialize the console, respecting the --no-color flag.
    console = Console(no_color=args.no_color)
    
    api_key = get_api_key()
    client = anthropic.Anthropic(api_key=api_key)
    
    if not os.path.exists(args.repo_path):
        console.print(f"[red]Error: Repository path '{args.repo_path}' does not exist[/red]")
        sys.exit(1)
    
    question = get_question(args, console)
    
    console.print(Panel(f"[bold]Repository:[/bold] {args.repo_path}\n[bold]Question:[/bold] {question}", 
                        title="[bold blue]Dynamic Code Analyzer[/bold blue]"))
    
    files = scan_repo_files(args.repo_path)
    # Post-filters
    if args.include_exts:
        include_exts = {e if e.startswith('.') else f'.{e}' for e in args.include_exts}
        files = [f for f in files if f.suffix.lower() in include_exts]
    if args.ignore_dirs:
        skip_set = set(args.ignore_dirs)
        files = [f for f in files if not any(skip in f.parts for skip in skip_set)]
    console.print(f"Found {len(files)} code files to analyze.\n")
    
    all_insights = []
    
    for i, file_path in enumerate(files, 1):
        console.print(f"[[bold]{i}/{len(files)}[/bold]] Analyzing [cyan]{file_path.name}[/cyan]...")
        analysis = analyze_file_with_claude(client, file_path, question, console, model=args.model, max_tokens=args.max_tokens, temperature=args.temperature)
        if not analysis: continue
        
        parsed = parse_json_response(analysis)
        if parsed and 'insights' in parsed:
            file_insights = parsed.get('insights', [])
            console.print(f"   Relevance: [bold yellow]{parsed.get('relevance', 'N/A')}[/bold yellow], Found [bold]{len(file_insights)}[/bold] insights.")
            
            if args.verbose and file_insights:
                for insight in file_insights:
                    console.print(f"     [bold]Finding:[/bold] {insight.get('finding', 'N/A')} (Line: {insight.get('line_number', 'N/A')})")
                    console.print(f"     [bold]Recommendation:[/bold] {insight.get('recommendation', 'N/A')}\n")
            
            for insight in file_insights:
                insight['file_path'] = str(file_path)
            all_insights.extend(file_insights)
        else:
            console.print("   [yellow]Could not parse a structured response from API.[/yellow]")
        
        time.sleep(1)
    
    # Create the final report object to pass to formatters.
    report = AnalysisReport(
        repo_path=args.repo_path,
        question=question,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        file_count=len(files),
        insights=all_insights
    )

    # Display console summary if requested.
    if 'console' in args.format:
        display_console_summary(console, report)

    # Save file-based reports if requested.
    file_formats = [f for f in args.format if f != 'console']
    if file_formats:
        save_reports(report, file_formats, args.output, console)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user.")
        sys.exit(1)
