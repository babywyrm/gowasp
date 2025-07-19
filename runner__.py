#!/usr/bin/env python3
import os
import sys
import json
import time
import subprocess
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import anthropic

# --- Constants and Configuration ---
CLAUDE_MODEL = "claude-3-5-sonnet-20241022"
MAX_WORKERS = 4
MAX_RETRIES = 3
SUPPORTED_EXTENSIONS = {
    '.go': 'go', '.py': 'python', '.java': 'java', '.js': 'javascript',
    '.jsx': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
    '.php': 'php', '.html': 'html', '.htm': 'html', '.css': 'css', '.sql': 'sql',
}
# Used for filtering Claude's results in Python
SEVERITY_LEVELS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

Finding = Dict[str, Any]

class Orchestrator:
    """
    Orchestrates security scans using a static Go scanner and the Claude AI.
    """
    def __init__(self, repo_path: Path, scanner_bin: Path, parallel: bool, debug: bool, severity: Optional[str]):
        self.repo_path = repo_path.resolve()
        self.scanner_bin = scanner_bin.resolve()
        self.parallel = parallel
        self.debug = debug
        self.severity = severity.upper() if severity else None
        
        self.api_key = os.getenv("CLAUDE_API_KEY")
        if not self.api_key:
            print("ERROR: CLAUDE_API_KEY environment variable not set.", file=sys.stderr)
            sys.exit(1)
            
        sanitized_repo_name = str(repo_path).strip('/').replace('/', '_')
        self.output_path = Path("output") / sanitized_repo_name
        os.makedirs(self.output_path, exist_ok=True)
        print(f"Outputs will be saved in: {self.output_path}")
        if self.severity:
            print(f"Filtering for minimum severity: {self.severity}")

    def _meets_severity_threshold(self, finding_severity: str) -> bool:
        """Checks if a finding's severity meets the user's threshold."""
        if not self.severity:
            return True  # If no filter is set, everything passes
        
        finding_level = SEVERITY_LEVELS.get(finding_severity.upper(), 0)
        threshold_level = SEVERITY_LEVELS.get(self.severity, 0)
        
        return finding_level >= threshold_level

    def run_static_scanner(self) -> List[Finding]:
        """Runs the gowasp scanner, passing the severity flag if provided."""
        cmd = [str(self.scanner_bin), "--dir", str(self.repo_path), "--output", "json"]
        # **THE FIX IS HERE: Pass the severity flag to the Go scanner**
        if self.severity:
            cmd.extend(["--severity", self.severity])
            
        print(f"\n1) Running static gowasp scanner...\n   Running: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True)

        if proc.returncode != 0:
            print(f"WARNING: scanner exited with code {proc.returncode}", file=sys.stderr)

        out = proc.stdout
        if self.debug:
            print("--- [DEBUG] Raw Scanner Output ---", file=sys.stderr)
            print(out, file=sys.stderr)
            print("--- [DEBUG] End Raw Scanner Output ---", file=sys.stderr)

        start = out.find('[')
        end = out.rfind(']') + 1
        if start < 0 or end <= start:
            print("ERROR: Could not find a JSON array `[...]` in the scanner's output.", file=sys.stderr)
            return []
        try:
            return json.loads(out[start:end])
        except json.JSONDecodeError:
            print("ERROR: Found a `[...]` block, but it was not valid JSON.", file=sys.stderr)
            return []

    def _get_files_to_scan(self) -> List[Path]:
        """Lists all source files for AI analysis."""
        skip_dirs = {'.git', 'node_modules', '__pycache__', 'vendor', 'build', 'dist'}
        files = []
        for p in self.repo_path.rglob('*'):
            if (p.is_file() and
                p.suffix.lower() in SUPPORTED_EXTENSIONS and
                not any(skip_dir in p.parts for skip_dir in skip_dirs)):
                files.append(p)
        return sorted(files)

    def _analyze_file_with_claude(self, file_path: Path) -> List[Finding]:
        """Analyzes a single file with Claude, with a robust prompt and retry logic."""
        client = anthropic.Anthropic(api_key=self.api_key)
        code = file_path.read_text(encoding='utf-8', errors='replace')
        if not code.strip() or len(code) > 100000:
            return []
        
        language = SUPPORTED_EXTENSIONS.get(file_path.suffix.lower(), "text")
        prompt = f"""You are a security expert analyzing code for OWASP Top 10 vulnerabilities.
FILE: {file_path}
LANGUAGE: {language}
CRITICAL: You must respond with a single, valid JSON object and nothing else.
The JSON object must have this exact structure:
{{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "total_issues": 0,
  "owasp_findings": [
    {{
      "category": "A03", "title": "SQL Injection", "severity": "HIGH",
      "line_number": 45, "vulnerable_code": "...", "explanation": "...", "fix": "..."
    }}
  ]
}}
CODE TO ANALYZE:
{code}
"""
        for attempt in range(MAX_RETRIES):
            try:
                resp = client.messages.create(model=CLAUDE_MODEL, max_tokens=3000, messages=[{"role": "user", "content": prompt}])
                text = resp.content[0].text.strip()
                if self.debug:
                    print(f"--- [DEBUG] Raw Claude Response for {file_path} ---", file=sys.stderr)
                    print(text, file=sys.stderr)
                    print(f"--- [DEBUG] End Raw Claude Response for {file_path} ---", file=sys.stderr)
                
                start = text.find('{')
                end = text.rfind('}') + 1
                if start >= 0 and end > start:
                    data = json.loads(text[start:end])
                    return data.get('owasp_findings', [])
                return []
            except anthropic.APIStatusError as e:
                if e.status_code == 529 and attempt < MAX_RETRIES - 1:
                    wait_time = 2 ** (attempt + 1)
                    print(f"WARNING: Claude API overloaded for {file_path}. Retrying in {wait_time}s...", file=sys.stderr)
                    time.sleep(wait_time)
                else:
                    raise e
            except Exception as e:
                print(f"ERROR: Unexpected error analyzing {file_path}: {e}", file=sys.stderr)
                return []
        return []

    def run_ai_scanner(self) -> List[Finding]:
        """Runs the Claude OWASP analysis and filters results by severity."""
        files = self._get_files_to_scan()
        ai_findings: List[Finding] = []
        run_mode = "parallel" if self.parallel else "sequential"
        print(f"\n2) Running Claude OWASP analysis...\n   (Running in {run_mode} mode on {len(files)} files)")

        def process_result(original_findings: List[Finding]) -> List[Finding]:
            """Filters findings by severity and adds source metadata."""
            processed = []
            for item in original_findings:
                if self._meets_severity_threshold(item.get("severity", "")):
                    item['source'] = 'claude'
                    processed.append(item)
            return processed

        if self.parallel:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                future_to_file = {executor.submit(self._analyze_file_with_claude, f): f for f in files}
                for i, future in enumerate(as_completed(future_to_file), 1):
                    fpath = future_to_file[future]
                    print(f"   [{i}/{len(files)}] Processing AI results for {fpath}")
                    try:
                        ofs = future.result()
                        for item in process_result(ofs): item['file'] = str(fpath)
                        ai_findings.extend(ofs)
                    except Exception as e:
                        print(f"   ERROR analyzing {fpath}: {e}", file=sys.stderr)
        else:
            for i, fpath in enumerate(files, 1):
                print(f"   [{i}/{len(files)}] Analyzing {fpath} with Claude...")
                try:
                    ofs = self._analyze_file_with_claude(fpath)
                    processed_findings = process_result(ofs)
                    for item in processed_findings: item['file'] = str(fpath)
                    ai_findings.extend(processed_findings)
                    time.sleep(0.5)
                except Exception as e:
                    print(f"   ERROR analyzing {fpath}: {e}", file=sys.stderr)
        return ai_findings

    def run(self) -> None:
        """Executes the full scan and merge workflow."""
        static_findings = self.run_static_scanner()
        for finding in static_findings:
            finding['source'] = 'gowasp'
        static_output_file = self.output_path / "static_findings.json"
        with open(static_output_file, "w") as f:
            json.dump(static_findings, f, indent=2)
        print(f"   → {len(static_findings)} static findings written to {static_output_file}")

        ai_findings = self.run_ai_scanner()
        ai_output_file = self.output_path / "ai_findings.json"
        with open(ai_output_file, "w") as f:
            json.dump(ai_findings, f, indent=2)
        print(f"   → {len(ai_findings)} AI findings written to {ai_output_file}")

        print("\n3) Merging and deduplicating findings...")
        combined: List[Finding] = []
        seen: set[Tuple[Any, ...]] = set()
        for f in static_findings + ai_findings:
            key = (f.get('file'), f.get('category'), f.get('title', f.get('rule_name', '')), f.get('line_number', f.get('line')))
            if key in seen:
                continue
            seen.add(key)
            combined.append(f)
        
        combined_output_file = self.output_path / "combined_findings.json"
        with open(combined_output_file, "w") as f:
            json.dump(combined, f, indent=2)
        print(f"   → {len(combined)} combined findings written to {combined_output_file}")

def main() -> None:
    """Parses command-line arguments and runs the orchestrator."""
    parser = argparse.ArgumentParser(description="Orchestrator for gowasp and Claude scanners.")
    parser.add_argument("repo_path", type=Path, help="Path to the repository to scan.")
    parser.add_argument("scanner_bin", type=Path, help="Path to the gowasp scanner binary.")
    parser.add_argument("--parallel", action="store_true", help="Run Claude analysis in parallel.")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode for verbose output.")
    # **THE FIX IS HERE: Add the severity argument**
    parser.add_argument(
        "--severity",
        type=str.upper,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Minimum severity to report (e.g., HIGH will show HIGH and CRITICAL)."
    )
    args = parser.parse_args()

    if not args.repo_path.is_dir():
        print(f"Error: '{args.repo_path}' is not a directory", file=sys.stderr)
        sys.exit(1)
    if not args.scanner_bin.is_file() or not os.access(args.scanner_bin, os.X_OK):
        print(f"Error: scanner binary '{args.scanner_bin}' not found or not executable", file=sys.stderr)
        sys.exit(1)

    orchestrator = Orchestrator(
        repo_path=args.repo_path,
        scanner_bin=args.scanner_bin,
        parallel=args.parallel,
        debug=args.debug,
        severity=args.severity
    )
    orchestrator.run()

if __name__ == "__main__":
    main()
