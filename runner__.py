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
SEVERITY_LEVELS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

Finding = Dict[str, Any]

class Orchestrator:
    """
    Orchestrates security scans using a static Go scanner and the Claude AI.
    """
    def __init__(self, repo_path: Path, scanner_bin: Path, parallel: bool, debug: bool, severity: Optional[str], profiles: str, static_rules: Optional[str], threat_model: bool, verbose: bool):
        self.repo_path = repo_path.resolve()
        self.scanner_bin = scanner_bin.resolve()
        self.parallel = parallel
        self.debug = debug
        self.severity = severity.upper() if severity else None
        self.profiles = [p.strip() for p in profiles.split(',')]
        self.static_rules = static_rules
        self.threat_model = threat_model
        self.verbose = verbose
        
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
        print(f"Using AI analysis profiles: {self.profiles}")

        self.prompt_templates = self._load_prompt_templates()

    def _load_prompt_templates(self) -> Dict[str, str]:
        """Loads all requested prompt templates from the prompts/ directory."""
        templates = {}
        profiles_to_load = self.profiles[:]
        if self.threat_model and 'attacker' not in profiles_to_load:
            profiles_to_load.append('attacker')

        for profile in profiles_to_load:
            prompt_file = Path("prompts") / f"{profile}_profile.txt"
            if not prompt_file.is_file():
                print(f"ERROR: Prompt file not found for profile '{profile}'. Expected at: {prompt_file}", file=sys.stderr)
                sys.exit(1)
            templates[profile] = prompt_file.read_text()
        print(f"   (Loaded {len(templates)} prompt templates)")
        return templates

    def _meets_severity_threshold(self, finding_severity: str) -> bool:
        """Checks if a finding's severity meets the user's threshold."""
        if not self.severity:
            return True
        finding_level = SEVERITY_LEVELS.get(finding_severity.upper(), 0)
        threshold_level = SEVERITY_LEVELS.get(self.severity, 0)
        return finding_level >= threshold_level

    def run_static_scanner(self) -> List[Finding]:
        """Runs the gowasp scanner and extracts the JSON array from its output."""
        cmd = [str(self.scanner_bin), "--dir", str(self.repo_path), "--output", "json"]
        if self.severity:
            cmd.extend(["--severity", self.severity])
        if self.static_rules:
            cmd.extend(["--rules", self.static_rules])
        if self.verbose:
            cmd.append("--verbose")
            
        print(f"\n1) Running static gowasp scanner...\n   Running: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"WARNING: scanner exited with code {proc.returncode}", file=sys.stderr)
        out = proc.stdout
        start = out.find('[')
        end = out.rfind(']') + 1
        if start < 0 or end <= start:
            return []
        try:
            return json.loads(out[start:end])
        except json.JSONDecodeError:
            return []

    def _get_files_to_scan(self) -> List[Path]:
        """Lists all source files for AI analysis, skipping common dependency directories."""
        skip_dirs = {'.git', 'node_modules', '__pycache__', 'vendor', 'build', 'dist'}
        files = []
        for p in self.repo_path.rglob('*'):
            if (p.is_file() and
                p.suffix.lower() in SUPPORTED_EXTENSIONS and
                not any(skip_dir in p.parts for skip_dir in skip_dirs)):
                files.append(p)
        return sorted(files)

    def _analyze_file_with_claude(self, file_path: Path, profile: str) -> Optional[Dict[str, Any]]:
        """Analyzes a single file with Claude and returns the full parsed JSON object."""
        client = anthropic.Anthropic(api_key=self.api_key)
        code = file_path.read_text(encoding='utf-8', errors='replace')
        if not code.strip() or len(code) > 100000:
            return None
        
        language = SUPPORTED_EXTENSIONS.get(file_path.suffix.lower(), "text")
        prompt = self.prompt_templates[profile].format(file_path=file_path, language=language, code=code)

        for attempt in range(MAX_RETRIES):
            try:
                resp = client.messages.create(model=CLAUDE_MODEL, max_tokens=3000, messages=[{"role": "user", "content": prompt}])
                text = resp.content[0].text.strip()
                start = text.find('{')
                end = text.rfind('}') + 1
                if start >= 0 and end > start:
                    return json.loads(text[start:end])
                return None
            except anthropic.APIStatusError as e:
                if e.status_code == 529 and attempt < MAX_RETRIES - 1:
                    wait_time = 2 ** (attempt + 1)
                    print(f"WARNING: Claude API overloaded for {file_path}. Retrying in {wait_time}s...", file=sys.stderr)
                    time.sleep(wait_time)
                else:
                    raise e
            except Exception as e:
                print(f"ERROR: Unexpected error analyzing {file_path}: {e}", file=sys.stderr)
                return None
        return None

    def _print_live_claude_summary(self, file_path: Path, result: Dict[str, Any], profile: str) -> None:
        """Prints a formatted summary of Claude's findings to stderr for real-time feedback."""
        print(f"\n--- Claude Live Analysis: {file_path} (Profile: {profile}) ---", file=sys.stderr)
        risk = result.get("overall_risk", "N/A")
        
        findings_key = next((key for key in result if key.endswith("_findings")), None)
        findings = result.get(findings_key, [])
        
        print(f"  Overall Risk: {risk} | Findings: {len(findings)}", file=sys.stderr)
        for f in findings:
            sev = f.get('severity', 'UNK')
            title = f.get('title', 'Unknown Issue')
            line = f.get('line_number', '?')
            print(f"    - [{sev}] {title} (Line: {line})", file=sys.stderr)
        print("--------------------------------------------------\n", file=sys.stderr)

    def run_ai_scanner(self) -> List[Finding]:
        """Runs the Claude analysis for each requested file-based profile."""
        files = self._get_files_to_scan()
        all_ai_findings: List[Finding] = []
        run_mode = "parallel" if self.parallel else "sequential"
        
        print(f"\n2) Running Claude File-by-File Analysis...\n   (Running in {run_mode} mode on {len(files)} files)")

        file_profiles = [p for p in self.profiles if p != 'attacker']

        for profile in file_profiles:
            print(f"\n--- Starting AI Profile: {profile} ---")
            profile_findings: List[Finding] = []

            def process_and_log(full_result: Optional[Dict[str, Any]], fpath: Path) -> List[Finding]:
                if not full_result:
                    return []
                
                if self.debug or self.verbose:
                    self._print_live_claude_summary(fpath, full_result, profile)

                findings_key = next((key for key in full_result if key.endswith("_findings")), None)
                original_findings = full_result.get(findings_key, [])
                
                processed = []
                for item in original_findings:
                    if self._meets_severity_threshold(item.get("severity", "")):
                        item['source'] = f'claude-{profile}'
                        item['file'] = str(fpath)
                        processed.append(item)
                return processed

            if self.parallel:
                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    future_to_file = {executor.submit(self._analyze_file_with_claude, f, profile): f for f in files}
                    for i, future in enumerate(as_completed(future_to_file), 1):
                        fpath = future_to_file[future]
                        print(f"   [{i}/{len(files)}] Processing AI results for {fpath}")
                        try:
                            full_result = future.result()
                            profile_findings.extend(process_and_log(full_result, fpath))
                        except Exception as e:
                            print(f"   ERROR analyzing {fpath}: {e}", file=sys.stderr)
            else:
                for i, fpath in enumerate(files, 1):
                    print(f"   [{i}/{len(files)}] Analyzing {fpath} with Claude...")
                    try:
                        full_result = self._analyze_file_with_claude(fpath, profile)
                        profile_findings.extend(process_and_log(full_result, fpath))
                        time.sleep(0.5)
                    except Exception as e:
                        print(f"   ERROR analyzing {fpath}: {e}", file=sys.stderr)
            
            all_ai_findings.extend(profile_findings)
            print(f"--- Completed AI Profile: {profile}, Found {len(profile_findings)} issues (after filtering) ---")
            
        return all_ai_findings

    def run_threat_model(self) -> None:
        """Performs a repo-level threat model with a robust retry mechanism."""
        print("\n+) Running Expert Mode: Attacker Perspective Threat Model...")
        files = self._get_files_to_scan()
        
        full_context = "".join(
            f"--- FILE: {fpath} ---\n{fpath.read_text(encoding='utf-8', errors='replace')}\n\n"
            for fpath in files
        )
        
        if not full_context:
            print("   No files found to analyze for threat model.")
            return

        prompt = self.prompt_templates['attacker'].format(code=full_context)
        
        # **THE FIX IS HERE: Add the same retry logic to this heavy-duty API call.**
        for attempt in range(MAX_RETRIES):
            try:
                client = anthropic.Anthropic(api_key=self.api_key)
                resp = client.messages.create(model=CLAUDE_MODEL, max_tokens=4000, messages=[{"role": "user", "content": prompt}])
                text = resp.content[0].text.strip()
                start = text.find('{')
                end = text.rfind('}') + 1
                if start >= 0 and end > start:
                    report = json.loads(text[start:end])
                    report_file = self.output_path / "threat_model_report.json"
                    with open(report_file, "w") as f:
                        json.dump(report, f, indent=2)
                    print(f"   → Threat model report written to {report_file}")
                    return # Success, exit the function
                else:
                    print("   ERROR: Claude did not return a valid JSON object for the threat model.", file=sys.stderr)
                    return # No point in retrying if the format is wrong
            except anthropic.APIStatusError as e:
                if e.status_code == 529 and attempt < MAX_RETRIES - 1:
                    # Use a longer, fixed wait time for this very large request.
                    wait_time = 20
                    print(f"WARNING: Claude API overloaded for threat model. Retrying in {wait_time} seconds...", file=sys.stderr)
                    time.sleep(wait_time)
                else:
                    print(f"   ERROR: Failed to generate threat model after {attempt + 1} attempts: {e}", file=sys.stderr)
                    return
            except Exception as e:
                print(f"   ERROR: Failed to generate threat model: {e}", file=sys.stderr)
                return
        print("   ERROR: All retries failed for threat model generation.", file=sys.stderr)


    def run(self) -> None:
        """Executes the full scan and merge workflow."""
        static_findings = self.run_static_scanner()
        static_output_file = self.output_path / "static_findings.json"
        with open(static_output_file, "w") as f:
            json.dump(static_findings, f, indent=2)
        print(f"   → {len(static_findings)} static findings written to {static_output_file}")

        ai_findings = self.run_ai_scanner()
        ai_output_file = self.output_path / "ai_findings.json"
        with open(ai_output_file, "w") as f:
            json.dump(ai_findings, f, indent=2)
        print(f"   → {len(ai_findings)} total AI findings written to {ai_output_file}")

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

        if self.threat_model:
            self.run_threat_model()

def main() -> None:
    """Parses command-line arguments and runs the orchestrator."""
    parser = argparse.ArgumentParser(
        description="Orchestrator for gowasp and Claude scanners.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("repo_path", type=Path, help="Path to the repository to scan.")
    parser.add_argument("scanner_bin", type=Path, help="Path to the gowasp scanner binary.")
    
    parser.add_argument("--profile", type=str.lower, default="owasp", help="Comma-separated list of AI analysis profiles (e.g., 'owasp,performance').")
    parser.add_argument("--static-rules", type=str, help="Comma-separated paths to static rule files for the Go scanner.")
    parser.add_argument("--severity", type=str.upper, choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Minimum severity to report.")
    
    parser.add_argument("--threat-model", action="store_true", help="Perform a repo-level, attacker-perspective threat model.")
    
    parser.add_argument("--parallel", action="store_true", help="Run Claude analysis in parallel.")
    parser.add_argument("--verbose", action="store_true", help="Show live Claude results and gowasp remediation advice.")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output for troubleshooting.")
    
    args = parser.parse_args()

    orchestrator = Orchestrator(
        repo_path=args.repo_path,
        scanner_bin=args.scanner_bin,
        parallel=args.parallel,
        debug=args.debug,
        severity=args.severity,
        profiles=args.profile,
        static_rules=args.static_rules,
        threat_model=args.threat_model,
        verbose=args.verbose
    )
    orchestrator.run()

if __name__ == "__main__":
    main()
