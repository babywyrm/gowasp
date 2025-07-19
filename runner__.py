#!/usr/bin/env python3
import os
import sys
import json
import time
import subprocess
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import anthropic

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
API_KEY = "sk-ant-lol"
CLAUDE_MODEL = "claude-3-5-sonnet-20241022"
MAX_WORKERS = 4  # Number of parallel threads for Claude API calls (if --parallel is used)
MAX_RETRIES = 3  # How many times to retry a failed API call

SUPPORTED_EXTENSIONS = {
    '.go': 'go', '.py': 'python', '.java': 'java', '.js': 'javascript',
    '.jsx': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
    '.php': 'php', '.html': 'html', '.htm': 'html', '.css': 'css', '.sql': 'sql',
}

# ----------------------------------------------------------------------
# Run static scanner and robustly extract JSON block
# ----------------------------------------------------------------------
def run_scanner(scanner_bin: str, repo_path: str):
    """
    Runs the gowasp scanner and intelligently extracts the JSON array from its mixed output.
    """
    cmd = [scanner_bin, "--dir", repo_path, "--output", "json"]
    print(f"Running: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)

    if proc.returncode != 0:
        print(f"WARNING: scanner exited with code {proc.returncode}", file=sys.stderr)

    out = proc.stdout
    start = out.find('[')
    end = out.rfind(']') + 1

    if start < 0 or end <= start:
        print("ERROR: Could not find a JSON array `[...]` in the scanner's output.", file=sys.stderr)
        return []

    json_text = out[start:end]
    try:
        return json.loads(json_text)
    except json.JSONDecodeError:
        print("ERROR: Found a `[...]` block, but it was not valid JSON.", file=sys.stderr)
        return []

# ----------------------------------------------------------------------
# List files for AI analysis
# ----------------------------------------------------------------------
def scan_repo_files(repo_path: str):
    skip_dirs = {
        '.git', 'node_modules', '__pycache__', 'vendor',
        'build', 'dist', '.pytest_cache', 'target', 'bin', 'obj',
    }
    files = []
    for p in Path(repo_path).rglob('*'):
        if not p.is_file():
            continue
        if any(skip in p.parts for skip in skip_dirs):
            continue
        if p.suffix.lower() in SUPPORTED_EXTENSIONS:
            files.append(p)
    return sorted(files)

# ----------------------------------------------------------------------
# Call Claude for OWASP Top-10 on one file, with retries
# ----------------------------------------------------------------------
def analyze_with_claude(file_path: Path):
    """
    Analyzes a file with Claude, using a robust prompt and retry logic for API errors.
    """
    client = anthropic.Anthropic(api_key=API_KEY)
    code = file_path.read_text(encoding='utf-8', errors='replace')
    if not code.strip() or len(code) > 100000: # Skip empty or very large files
        return []
        
    language = SUPPORTED_EXTENSIONS.get(file_path.suffix.lower(), "text")
    
    prompt = f"""You are a security expert analyzing code for OWASP Top 10 vulnerabilities.

FILE: {file_path}
LANGUAGE: {language}

OWASP TOP 10 ANALYSIS CHECKLIST:
A01 - BROKEN ACCESS CONTROL
A02 - CRYPTOGRAPHIC FAILURES
A03 - INJECTION
A04 - INSECURE DESIGN
A05 - SECURITY MISCONFIGURATION
A06 - VULNERABLE COMPONENTS
A07 - AUTHENTICATION FAILURES
A08 - SOFTWARE/DATA INTEGRITY
A09 - LOGGING/MONITORING FAILURES
A10 - SERVER-SIDE REQUEST FORGERY

CRITICAL: You must respond with a single, valid JSON object and nothing else.
The JSON object must have this exact structure:
{{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "total_issues": 0,
  "owasp_findings": [
    {{
      "category": "A03",
      "title": "SQL Injection Vulnerability",
      "severity": "HIGH",
      "line_number": 45,
      "vulnerable_code": "SELECT * FROM users WHERE id = " + userId,
      "explanation": "Direct string concatenation creates SQL injection risk",
      "fix": "Use parameterized queries: SELECT * FROM users WHERE id = ?",
      "impact": "Attacker can read/modify database"
    }}
  ]
}}

CODE TO ANALYZE:
{code}
"""

    for attempt in range(MAX_RETRIES):
        try:
            resp = client.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=3000,
                messages=[{"role": "user", "content": prompt}],
            )
            text = resp.content[0].text.strip()
            start = text.find('{')
            end = text.rfind('}') + 1
            if start >= 0 and end > start:
                data = json.loads(text[start:end])
                return data.get('owasp_findings', [])
            else:
                return []
        except anthropic.APIStatusError as e:
            if e.status_code == 529 and attempt < MAX_RETRIES - 1:
                wait_time = 2 ** (attempt + 1)
                print(f"WARNING: Claude API overloaded for {file_path}. Retrying in {wait_time} seconds...", file=sys.stderr)
                time.sleep(wait_time)
            else:
                raise e
        except Exception as e:
            print(f"ERROR: An unexpected error occurred while analyzing {file_path}: {e}", file=sys.stderr)
            return []
    return []

# ----------------------------------------------------------------------
# Main orchestration
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Orchestrator for gowasp and Claude scanners.")
    parser.add_argument("repo_path", help="Path to the repository to scan.")
    parser.add_argument("scanner_bin", help="Path to the gowasp scanner binary.")
    parser.add_argument("--parallel", action="store_true", help="Run Claude analysis in parallel (might hit rate limits).")
    args = parser.parse_args()

    output_dir = "output"

    if not os.path.isdir(args.repo_path):
        print(f"Error: '{args.repo_path}' is not a directory", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(args.scanner_bin) or not os.access(args.scanner_bin, os.X_OK):
        print(f"Error: scanner binary '{args.scanner_bin}' not found or not executable", file=sys.stderr)
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    # 1) Static scan
    print("1) Running static gowasp scanner...")
    static_findings = run_scanner(args.scanner_bin, args.repo_path)
    with open(f"{output_dir}/static_findings.json", "w") as f:
        json.dump(static_findings, f, indent=2)
    print(f"   → {len(static_findings)} static findings written to {output_dir}/static_findings.json")

    # 2) AI scan
    print("2) Running Claude OWASP analysis...")
    files = scan_repo_files(args.repo_path)
    ai_findings = []

    if args.parallel:
        print("   (Running in parallel mode)")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_file = {executor.submit(analyze_with_claude, f): f for f in files}
            for i, future in enumerate(as_completed(future_to_file), 1):
                fpath = future_to_file[future]
                print(f"   [{i}/{len(files)}] Processing AI results for {fpath}")
                try:
                    ofs = future.result()
                    for item in ofs:
                        item['file'] = str(fpath)
                    ai_findings.extend(ofs)
                except Exception as e:
                    print(f"   ERROR analyzing {fpath}: {e}", file=sys.stderr)
    else:
        print("   (Running in sequential mode)")
        for i, fpath in enumerate(files, 1):
            print(f"   [{i}/{len(files)}] Analyzing {fpath} with Claude...")
            try:
                ofs = analyze_with_claude(fpath)
                for item in ofs:
                    item['file'] = str(fpath)
                ai_findings.extend(ofs)
                time.sleep(0.5) # Be nice to the API
            except Exception as e:
                print(f"   ERROR analyzing {fpath}: {e}", file=sys.stderr)

    with open(f"{output_dir}/ai_findings.json", "w") as f:
        json.dump(ai_findings, f, indent=2)
    print(f"   → {len(ai_findings)} AI findings written to {output_dir}/ai_findings.json")

    # 3) Merge & dedupe
    print("3) Merging and deduplicating findings...")
    combined = []
    seen = set()
    for f in static_findings + ai_findings:
        key = (
            f.get('file'),
            f.get('category'),
            f.get('title', f.get('rule_name', '')),
            f.get('line_number', f.get('line'))
        )
        if key in seen:
            continue
        seen.add(key)
        combined.append(f)
    with open(f"{output_dir}/combined_findings.json", "w") as f:
        json.dump(combined, f, indent=2)
    print(f"   → {len(combined)} combined findings written to {output_dir}/combined_findings.json")

if __name__ == "__main__":
    main()
