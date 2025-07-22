#!/usr/bin/env python3
"""
A 'lite' dynamic code analyzer that scans a repository, sends individual files
to the Claude API for analysis against a user-provided question, and summarizes
the findings with proper attribution.

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

import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Defines which file extensions are eligible for analysis.
SUPPORTED_EXTENSIONS = {'.py', '.go', '.java', '.js', '.ts', '.php', '.rb', '.jsx', '.tsx'}

def get_api_key() -> str:
    """
    Retrieves the Claude API key from an environment variable.
    Exits if the key is not set.
    """
    api_key = os.getenv('CLAUDE_API_KEY')
    if not api_key:
        print("Error: CLAUDE_API_KEY environment variable not set.")
        print("Please set it with: export CLAUDE_API_KEY=your_api_key_here")
        sys.exit(1)
    return api_key

def get_dynamic_prompt(file_path: Path, code_content: str, question: str) -> str:
    """
    Creates the prompt for the Claude API, asking for a structured JSON response.
    
    Args:
        file_path: The path to the file being analyzed.
        code_content: The content of the file.
        question: The user's analysis question.
        
    Returns:
        A formatted prompt string.
    """
    return f"""You are an expert code analyst helping to answer specific questions about codebases.

FILE: {file_path}
LANGUAGE: {file_path.suffix}

QUESTION TO ANALYZE: {question}

Please analyze the following code in the context of the question above. 
Provide actionable insights and specific recommendations.

PROVIDE OUTPUT IN JSON FORMAT:
{{
  "relevance": "HIGH|MEDIUM|LOW|NONE",
  "insights": [
    {{
      "finding": "Description of what you found relevant to the question",
      "line_number": 45,
      "recommendation": "Specific actionable recommendation"
    }}
  ]
}}

CODE TO ANALYZE:
{code_content}

Focus on findings that directly relate to the question asked. Be specific and actionable."""

def analyze_file_with_claude(client: anthropic.Anthropic, file_path: Path, question: str, console: Console) -> str | None:
    """
    Analyzes a single file using the Claude API.
    
    Args:
        client: The initialized Anthropic API client.
        file_path: The path to the file to analyze.
        question: The user's analysis question.
        console: The rich console object for printing status messages.
        
    Returns:
        The API response text, or None if an error occurs or the file is skipped.
    """
    try:
        content = file_path.read_text(encoding='utf-8', errors='replace')
        if not content.strip():
            return None
        if len(content) > 100000:
            console.print(f"   [yellow]Skipping {file_path.name} (file too large)[/yellow]")
            return None
        
        console.print(f"   [dim]File size: {len(content)} characters[/dim]")
        prompt = get_dynamic_prompt(file_path, content, question)
        
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
    except Exception as e:
        console.print(f"   [red]Error analyzing {file_path.name}: {e}[/red]")
        return None

def parse_json_response(response_text: str) -> dict | None:
    """
    Safely parses a JSON object from the API's potentially unstructured text response.
    
    Args:
        response_text: The raw text response from the Claude API.
        
    Returns:
        A dictionary if parsing is successful, otherwise None.
    """
    try:
        start = response_text.find('{')
        end = response_text.rfind('}') + 1
        if start >= 0 and end > start:
            json_str = response_text[start:end]
            return json.loads(json_str)
    except json.JSONDecodeError:
        pass
    return None

def scan_repo_files(repo_path: str) -> list[Path]:
    """
    Scans a repository for supported file types, skipping common dependency and build directories.
    
    Args:
        repo_path: The path to the repository directory.
        
    Returns:
        A sorted list of file paths to be analyzed.
    """
    repo = Path(repo_path)
    files = []
    skip_dirs = {'.git', 'node_modules', '__pycache__', 'vendor', 'build', 'dist', '.pytest_cache', 'target'}
    for file_path in repo.rglob("*"):
        if (file_path.is_file() and 
            file_path.suffix in SUPPORTED_EXTENSIONS and 
            not any(skip in file_path.parts for skip in skip_dirs)):
            files.append(file_path)
    return sorted(files)

def get_question(args: argparse.Namespace) -> str:
    """
    Gets the analysis question from command-line arguments or prompts the user if not provided.
    
    Args:
        args: The parsed command-line arguments.
        
    Returns:
        The analysis question as a string.
    """
    if args.question:
        return args.question
    
    console = Console()
    console.print("\n[bold cyan]What would you like to analyze about this codebase?[/bold cyan]")
    console.print("[dim]Examples:[/dim]")
    console.print("  [dim]- How can we improve the data model?[/dim]")
    console.print("  [dim]- What are the main architectural patterns used?[/dim]")
    console.print("  [dim]- Where are the performance bottlenecks?[/dim]")
    console.print("  [dim]- How can we improve error handling?[/dim]")
    console.print()
    question = input("Enter your question: ").strip()
    if not question:
        console.print("[red]No question provided. Exiting.[/red]")
        sys.exit(1)
    return question

def print_summary(console: Console, all_insights: list, file_count: int) -> None:
    """
    Prints a final, formatted summary of the analysis, including top recommendations
    and the most vulnerable files.
    
    Args:
        console: The rich console object for printing.
        all_insights: A list of all insight dictionaries gathered during the analysis.
        file_count: The total number of files analyzed.
    """
    console.print(Panel("[bold green]Analysis Complete[/bold green]", border_style="green", expand=False))
    
    # Create and display a table for the top recommendations.
    recommendations_table = Table(title="[bold yellow]Top 5 Key Recommendations[/bold yellow]")
    recommendations_table.add_column("Recommendation", style="cyan", no_wrap=False)
    recommendations_table.add_column("File", style="magenta", no_wrap=True)
    
    for insight in all_insights[:5]:
        recommendations_table.add_row(
            insight.get('recommendation', 'N/A'),
            Path(insight.get('file_path', 'Unknown')).name
        )
    
    # Count findings per file to identify the most vulnerable ones.
    file_paths_with_vulns = [insight['file_path'] for insight in all_insights if 'file_path' in insight]
    vuln_file_counts = Counter(file_paths_with_vulns)
    
    vulnerable_files_table = Table(title="[bold red]Most Vulnerable Files[/bold red]")
    vulnerable_files_table.add_column("File", style="magenta", no_wrap=True)
    vulnerable_files_table.add_column("Findings Count", style="red", justify="right")

    for file_path, count in vuln_file_counts.most_common(5):
        vulnerable_files_table.add_row(Path(file_path).name, str(count))

    console.print(f"\nAnalyzed [bold]{file_count}[/bold] files and found [bold]{len(all_insights)}[/bold] total insights.\n")
    if all_insights:
        console.print(recommendations_table)
        console.print(vulnerable_files_table)

def create_parser() -> argparse.ArgumentParser:
    """Creates and configures the command-line argument parser."""
    parser = argparse.ArgumentParser(description="A 'lite' dynamic code analyzer using Claude.")
    parser.add_argument('repo_path', help='Path to the repository to analyze')
    parser.add_argument('question', nargs='?', help='Analysis question (will prompt if not provided)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Print detailed insights for each file as they are found.')
    return parser

def main() -> None:
    """
    Main execution function that orchestrates the analysis process.
    """
    parser = create_parser()
    args = parser.parse_args()
    
    console = Console()
    
    api_key = get_api_key()
    client = anthropic.Anthropic(api_key=api_key)
    
    repo_path = args.repo_path
    if not os.path.exists(repo_path):
        console.print(f"[red]Error: Repository path '{repo_path}' does not exist[/red]")
        sys.exit(1)
    
    question = get_question(args)
    
    console.print(Panel(f"[bold]Repository:[/bold] {repo_path}\n[bold]Question:[/bold] {question}", 
                        title="[bold blue]Dynamic Code Analyzer[/bold blue]", 
                        border_style="blue"))
    
    files = scan_repo_files(repo_path)
    console.print(f"Found {len(files)} code files to analyze.\n")
    
    all_insights = []
    
    for i, file_path in enumerate(files, 1):
        console.print(f"[[bold]{i}/{len(files)}[/bold]] Analyzing [cyan]{file_path.name}[/cyan]...")
        analysis = analyze_file_with_claude(client, file_path, question, console)
        if not analysis:
            continue
        
        parsed = parse_json_response(analysis)
        if parsed and 'insights' in parsed:
            file_insights = parsed.get('insights', [])
            relevance = parsed.get('relevance', 'UNKNOWN')
            console.print(f"   Relevance: [bold yellow]{relevance}[/bold yellow], Found [bold]{len(file_insights)}[/bold] insights.")
            
            # If verbose mode is on, print the details for this file immediately.
            if args.verbose and file_insights:
                for insight in file_insights:
                    console.print(f"     [bold]Finding:[/bold] {insight.get('finding', 'N/A')}")
                    console.print(f"     [bold]Line:[/bold] {insight.get('line_number', 'N/A')}")
                    console.print(f"     [bold]Recommendation:[/bold] {insight.get('recommendation', 'N/A')}\n")
            
            # Add the file path to each insight for later attribution in the summary.
            for insight in file_insights:
                insight['file_path'] = str(file_path)
            
            all_insights.extend(file_insights)
        else:
            console.print("   [yellow]Could not parse a structured response from API.[/yellow]")
        
        # A simple delay to respect potential API rate limits.
        time.sleep(1)
    
    print_summary(console, all_insights, len(files))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user.")
        sys.exit(1)
