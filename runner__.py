#!/usr/bin/env python3
import os
import sys
import json
import time
import subprocess
import argparse
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import logging
from tqdm import tqdm
import anthropic
import csv
from enum import Enum
from typing import TypedDict

# --- Constants / Configuration ---
CLAUDE_MODEL = "claude-3-5-sonnet-20241022"
MAX_WORKERS = 4
MAX_RETRIES = 3
CHUNK_SIZE = 2000  # lines per file chunk
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB per file safeguard

SUPPORTED_EXTENSIONS = {
    '.go': 'go', '.py': 'python', '.java': 'java', '.js': 'javascript',
    '.jsx': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
    '.php': 'php', '.html': 'html', '.htm': 'html', '.css': 'css', '.sql': 'sql',
}


class Severity(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


class Finding(TypedDict, total=False):
    severity: str
    file: str
    line_number: int
    category: str
    title: str
    source: str


# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)


class Orchestrator:
    """Coordinates scrynet static scan, Claude AI analysis, and threat modeling."""

    def __init__(self, repo_path: Path, scanner_bin: Path, parallel: bool, debug: bool,
                 severity: Optional[str], profiles: str, static_rules: Optional[str],
                 threat_model: bool, verbose: bool):
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
            logger.error("CLAUDE_API_KEY environment variable not set.")
            sys.exit(1)

        sanitized_repo_name = str(repo_path).strip('/').replace('/', '_')
        self.output_path = Path("output") / sanitized_repo_name
        os.makedirs(self.output_path, exist_ok=True)
        logger.info(f"Outputs will be saved in: {self.output_path}")
        if self.severity:
            logger.info(f"Filtering for minimum severity: {self.severity}")
        logger.info(f"Using AI analysis profiles: {self.profiles}")

        self.prompt_templates = self._load_prompt_templates()

    def _load_prompt_templates(self) -> Dict[str, str]:
        """Load profile-specific AI prompts from prompts/ directory."""
        templates: Dict[str, str] = {}
        profiles_to_load = self.profiles[:]
        if self.threat_model and 'attacker' not in profiles_to_load:
            profiles_to_load.append('attacker')
        for profile in profiles_to_load:
            prompt_file = Path("prompts") / f"{profile}_profile.txt"
            if not prompt_file.is_file():
                logger.error(f"Prompt file not found: {prompt_file}")
                sys.exit(1)
            templates[profile] = prompt_file.read_text(encoding="utf-8")
        logger.info(f"   (Loaded {len(templates)} prompt templates)")
        return templates

    def _meets_severity_threshold(self, finding_severity: str) -> bool:
        """Check if finding meets severity filter threshold."""
        if not self.severity:
            return True
        try:
            finding_level = Severity[finding_severity.upper()].value
            threshold_level = Severity[self.severity].value
            return finding_level <= threshold_level
        except KeyError:
            return False

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON object from model output using regex fallback."""
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON: {e}")
        return None

    def run_static_scanner(self) -> List[Finding]:
        """Invoke scrynet scanner binary and parse JSON results."""
        cmd = [str(self.scanner_bin), "--dir", str(self.repo_path), "--output", "json"]
        if self.severity:
            cmd.extend(["--severity", self.severity])
        if self.static_rules:
            cmd.extend(["--rules", self.static_rules])
        if self.verbose:
            cmd.append("--verbose")
        logger.info("1) Running static scrynet scanner...")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"scrynet scanner failed: {e.stderr}")
            return []
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
        """List source files, excluding dependency/build dirs."""
        skip_dirs = {'.git', 'node_modules', '__pycache__', 'vendor', 'build', 'dist'}
        files: List[Path] = []
        for p in self.repo_path.rglob('*'):
            if (p.is_file() and
                p.suffix.lower() in SUPPORTED_EXTENSIONS and
                not any(skip_dir in p.parts for skip_dir in skip_dirs)):
                if p.stat().st_size <= MAX_FILE_SIZE:
                    files.append(p)
                else:
                    logger.warning(f"Skipping {p}, file exceeds {MAX_FILE_SIZE} bytes.")
        return sorted(files)

    def _chunk_file(self, file_path: Path) -> List[str]:
        """Split large file into chunks to avoid token limits."""
        with file_path.open(encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if len(lines) <= CHUNK_SIZE:
            return ["".join(lines)]
        return [
            "".join(lines[i:i+CHUNK_SIZE])
            for i in range(0, len(lines), CHUNK_SIZE)
        ]

    def _analyze_file_with_claude(self, file_path: Path, profile: str) -> Optional[Dict[str, Any]]:
        """Send file contents (chunked if needed) to Claude and parse JSON response."""
        client = anthropic.Anthropic(api_key=self.api_key)
        code_chunks = self._chunk_file(file_path)
        language = SUPPORTED_EXTENSIONS.get(file_path.suffix.lower(), "text")
        for chunk in code_chunks:
            if not chunk.strip():
                continue
            try:
                prompt = self.prompt_templates[profile].format(file_path=file_path, language=language, code=chunk)
            except KeyError as e:
                logger.error(f"Prompt template for {profile} missing placeholder: {e}")
                return None
            for attempt in range(MAX_RETRIES):
                try:
                    resp = client.messages.create(
                        model=CLAUDE_MODEL,
                        max_tokens=3000,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    parsed = self._extract_json(resp.content[0].text.strip())
                    if parsed:
                        return parsed
                except anthropic.APIStatusError as e:
                    if e.status_code == 529 and attempt < MAX_RETRIES - 1:
                        wait_time = 2 ** (attempt + 1)
                        logger.warning(f"Claude API overloaded for {file_path}. Retrying in {wait_time}s...")
                        time.sleep(wait_time)
                    else:
                        raise e
                except Exception as e:
                    logger.error(f"Unexpected error analyzing {file_path}: {e}")
                    return None
        return None

    def _print_live_claude_summary(self, file_path: Path, result: Dict[str, Any], profile: str) -> None:
        """Render inline summary of model findings for a single file."""
        logger.info(f"--- Claude Analysis: {file_path} (Profile: {profile}) ---")
        risk = result.get("overall_risk", "N/A")
        findings_key = next((key for key in result if key.endswith("_findings")), None)
        findings = result.get(findings_key, [])
        logger.info(f"  Overall Risk: {risk} | Findings: {len(findings)}")
        for f in findings:
            sev = f.get('severity', 'UNK')
            title = f.get('title', 'Unknown Issue')
            line = f.get('line_number', '?')
            logger.info(f"    - [{sev}] {title} (Line: {line})")

    def run_ai_scanner(self) -> List[Finding]:
        """Iterate over files, run AI analysis per profile, collect findings."""
        files = self._get_files_to_scan()
        all_ai_findings: List[Finding] = []
        run_mode = "parallel" if self.parallel else "sequential"
        logger.info(f"2) Running Claude File-by-File Analysis ({run_mode} mode) on {len(files)} files")
        file_profiles = [p for p in self.profiles if p != 'attacker']
        for profile in file_profiles:
            logger.info(f"--- Starting AI Profile: {profile} ---")
            profile_findings: List[Finding] = []
            def process_and_log(full_result: Optional[Dict[str, Any]], fpath: Path) -> List[Finding]:
                if not full_result:
                    return []
                if self.debug or self.verbose:
                    self._print_live_claude_summary(fpath, full_result, profile)
                findings_key = next((key for key in full_result if key.endswith("_findings")), None)
                original_findings = full_result.get(findings_key, [])
                processed: List[Finding] = []
                for item in original_findings:
                    if self._meets_severity_threshold(item.get("severity", "")):
                        item['source'] = f'claude-{profile}'
                        item['file'] = str(fpath)
                        processed.append(item)
                return processed
            iterator = tqdm(files, desc=f"Profile: {profile}", unit="file", disable=not self.verbose)
            for fpath in iterator:
                try:
                    full_result = self._analyze_file_with_claude(fpath, profile)
                    profile_findings.extend(process_and_log(full_result, fpath))
                    if not self.parallel:
                        time.sleep(0.5)
                except Exception as e:
                    logger.error(f"Error analyzing {fpath}: {e}")
            all_ai_findings.extend(profile_findings)
            logger.info(f"--- Completed AI Profile: {profile}, Found {len(profile_findings)} issues (after filtering) ---")
        return all_ai_findings

    def run_threat_model(self) -> None:
        """Aggregate full repo context, run attacker-perspective threat model via Claude."""
        logger.info("+) Running Attacker-Perspective Threat Model...")
        files = self._get_files_to_scan()
        full_context = "".join(
            f"--- FILE: {fpath} ---\n{fpath.read_text(encoding='utf-8', errors='replace')}\n\n"
            for fpath in files
        )
        if not full_context:
            logger.warning("No files found for threat model.")
            return
        try:
            prompt = self.prompt_templates['attacker'].format(code=full_context)
        except KeyError as e:
            logger.error(f"Attacker template missing placeholder: {e}")
            return
        for attempt in range(MAX_RETRIES):
            try:
                client = anthropic.Anthropic(api_key=self.api_key)
                resp = client.messages.create(
                    model=CLAUDE_MODEL,
                    max_tokens=4000,
                    messages=[{"role": "user", "content": prompt}]
                )
                parsed = self._extract_json(resp.content[0].text.strip())
                if parsed:
                    report_file = self.output_path / "threat_model_report.json"
                    with open(report_file, "w", encoding="utf-8") as f:
                        json.dump(parsed, f, indent=2)
                    logger.info(f"Threat model report written to {report_file}")
                    return
                else:
                    logger.error("Claude did not return valid JSON for threat model")
                    return
            except anthropic.APIStatusError as e:
                if e.status_code == 529 and attempt < MAX_RETRIES - 1:
                    wait_time = 20
                    logger.warning(f"Claude API overloaded for threat model. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"Threat model generation failed: {e}")
                    return
            except Exception as e:
                logger.error(f"Threat model error: {e}")
                return
        logger.error("All retries failed for threat model generation")

    def run(self) -> None:
        """Execute static scan, AI analysis, merge, and export findings."""
        static_findings = self.run_static_scanner()
        for finding in static_findings:
            finding['source'] = 'scrynet'
        static_output_file = self.output_path / "static_findings.json"
        with open(static_output_file, "w", encoding="utf-8") as f:
            json.dump(static_findings, f, indent=2)
        logger.info(f"{len(static_findings)} static findings written to {static_output_file}")

        ai_findings = self.run_ai_scanner()
        ai_output_file = self.output_path / "ai_findings.json"
        with open(ai_output_file, "w", encoding="utf-8") as f:
            json.dump(ai_findings, f, indent=2)
        logger.info(f"{len(ai_findings)} AI findings written to {ai_output_file}")

        logger.info("3) Merging and deduplicating findings...")
        combined: List[Finding] = []
        seen: set[Tuple[Any, ...]] = set()
        for f in static_findings + ai_findings:
            key = (
                Path(f.get('file', '')).as_posix(),
                f.get('category', '').lower().strip(),
                f.get('title', f.get('rule_name', '')).lower().strip(),
                str(f.get('line_number', f.get('line', '')))
            )
            if key in seen:
                continue
            seen.add(key)
            combined.append(f)

        combined.sort(
            key=lambda x: (
                Severity[x.get("severity", "LOW").upper()].value
                if x.get("severity", "").upper() in Severity.__members__ else 99,
                x.get("file", ""),
                str(x.get("line_number", x.get("line", "")))
            )
        )

        combined_output_file = self.output_path / "combined_findings.json"
        with open(combined_output_file, "w", encoding="utf-8") as f:
            json.dump(combined, f, indent=2)
        logger.info(f"{len(combined)} combined findings written to {combined_output_file}")

        csv_output_file = self.output_path / "combined_findings.csv"
        with open(csv_output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Severity", "File", "Line", "Category", "Title", "Source"])
            for item in combined:
                writer.writerow([
                    item.get("severity", ""),
                    item.get("file", ""),
                    item.get("line_number", item.get("line", "")),
                    item.get("category", ""),
                    item.get("title", item.get("rule_name", "")),
                    item.get("source", "")
                ])
        logger.info(f"CSV export written to {csv_output_file}")

        md_output_file = self.output_path / "combined_findings.md"
        with open(md_output_file, "w", encoding="utf-8") as f:
            f.write("| Severity | File | Line | Category | Title | Source |\n")
            f.write("|----------|------|------|----------|-------|--------|\n")
            for item in combined:
                f.write(
                    f"| {item.get('severity','')} "
                    f"| {item.get('file','')} "
                    f"| {item.get('line_number', item.get('line',''))} "
                    f"| {item.get('category','')} "
                    f"| {item.get('title', item.get('rule_name',''))} "
                    f"| {item.get('source','')} |\n"
                )
        logger.info(f"Markdown export written to {md_output_file}")

        if self.threat_model:
            self.run_threat_model()


def main() -> None:
    """CLI parser and entrypoint."""
    parser = argparse.ArgumentParser(
        description="Orchestrator for scrynet and Claude scanners.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("repo_path", type=Path, help="Path to repo to scan.")
    parser.add_argument("scanner_bin", type=Path, help="Path to scrynet scanner binary.")
    parser.add_argument("--profile", type=str.lower, default="owasp",
                        help="Comma-separated list of AI profiles (e.g., 'owasp,performance').")
    parser.add_argument("--static-rules", type=str,
                        help="Comma-separated paths to static rule files for scrynet.")
    parser.add_argument("--severity", type=str.upper,
                        choices=[s.name for s in Severity],
                        help="Minimum severity to report.")
    parser.add_argument("--threat-model", action="store_true",
                        help="Perform repo-level attacker-perspective threat model.")
    parser.add_argument("--parallel", action="store_true",
                        help="Run Claude analysis in parallel.")
    parser.add_argument("--verbose", action="store_true",
                        help="Show progress bars + live results.")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug mode for troubleshooting.")
    args = parser.parse_args()

    if not args.repo_path.is_dir():
        logger.error(f"Error: '{args.repo_path}' is not a directory")
        sys.exit(1)
    if not args.scanner_bin.is_file() or not os.access(args.scanner_bin, os.X_OK):
        logger.error(f"Error: scanner binary '{args.scanner_bin}' not found or not executable")
        sys.exit(1)

    if args.debug:
        logger.setLevel(logging.DEBUG)

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

