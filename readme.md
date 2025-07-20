# GOWASP Hybrid Security Scanner 🎉  ( Beta )

Do you hate reviews.

Do you love CTFs.

Do you hate java contorllers.

Do you love having more time to not look at screens.

Do you miss the 90s.

# Read On 

GOWASP is a lightweight, multi-language static analysis tool that detects OWASP Top 10 security issues—and more—in your source code. 

It operates in two modes:

1.  **Standalone Go Scanner:** A fast, regex-based scanner perfect for quick checks and CI/CD integration.
2.  **Python Orchestrator:** A powerful wrapper that combines the Go scanner's speed with the deep contextual analysis of **Claude AI**, providing a comprehensive, multi-layered security report.

It supports Go, JS, Python, Java, PHP, HTML, and can output in text, JSON, or Markdown.

---

## 🚀 Features

### Core Scanner (`scanner`)

-   Multi-language scanning (Go, JS, Python, Java, HTML, PHP…)
-   OWASP Top 10 rule set with CRITICAL/HIGH/MEDIUM/LOW severities
-   Custom rules via JSON files (`--rules`)
-   Git diff scanning (`--git-diff`), ignore globs (`--ignore`)
-   Output formats: `text`, `json`, `markdown` (`--output`)
-   CI/CD safe: `--exit-high` fails the build on critical issues
-   GitHub PR comments (`--github-pr`)

### Python Orchestrator (`runner__.py`)

-   **Hybrid Analysis:** Combines the Go scanner's static findings with Claude AI's contextual OWASP analysis.
-   **Traceability:** Adds a `source` field (`"gowasp"` or `"claude"`) to every finding in the final report.
-   **Organized Outputs:** Creates a unique output directory for each scanned repository (e.g., `output/dvja_src/`).
-   **Secure by Default:** Securely reads the `CLAUDE_API_KEY` from your environment, not from the code.
-   **Flexible Execution:** Supports both safe sequential mode and a faster `--parallel` mode for AI calls.

---

## 🔧 Installation

The setup is a two-step process: first build the Go scanner, then set up the Python environment.

### 1. Build the Go Scanner

```bash
git clone https://github.com/babywyrm/gowasp.git
cd gowasp/gowasp

# Build the scanner binary
go build -o scanner .
```

### 2. Set up the Python Orchestrator

The orchestrator requires Python 3 and the Anthropic library.

```bash
# Install the required library
pip install anthropic

# You are now ready to run either the standalone scanner or the orchestrator
```

---

## 📖 Usage

You can run the tool in two ways, depending on your needs.

### Mode 1: Standalone Static Scanner

This is fast, free, and ideal for CI. It uses only the Go binary and your JSON rule files.

```bash
./scanner --help
```

| Flag | Description |
| :--- | :--- |
| `--dir` | Directory to scan (default `.`) |
| `--rules` | Comma-separated JSON rule files |
| `--severity` | Minimum severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `--ignore` | Comma-separated glob patterns to skip |
| `--git-diff` | Scan only files changed in last commit |
| `--output` | `text`, `json`, `markdown` |
| `--verbose` | Show remediation advice |
| `--exit-high`| Exit code 1 if any HIGH severity is found |
| `--github-pr`| Post Markdown report to GitHub PR |
| `--debug` | Enable internal logging |

### Mode 2: Hybrid AI Scan Orchestrator

This provides the most comprehensive analysis by combining the static scanner with Claude AI. **Note:** This uses the Claude API and will incur costs based on your usage.

**IMPORTANT: Set Your API Key**
Before running, you must set your Claude API key as an environment variable. The script will **not** run without it.

```bash
export CLAUDE_API_KEY="sk-ant-api03-..."
```

**Run the Orchestrator:**

```bash
python3 runner__.py <repo_path> <scanner_bin> [options]
```

| Flag | Description |
| :--- | :--- |
| `--parallel` | Run Claude analysis in parallel (faster, but may hit rate limits). |
| `--debug` | Enable verbose debug output for both scanners. |
| `--severity` | Minimum severity to report from the **static scanner only**. |

---

## 🎯 Examples

### Standalone Scanner Examples

```bash
# Quick text scan of the current directory
./scanner --dir .

# Markdown report, HIGH severity only
./scanner --dir ../dvja --severity HIGH --output markdown

# Use multiple rule sets for a deeper static scan
./scanner --rules=rules/rules_core.json,rules/rules_infra.json --dir .

# Only scan files changed in the last git commit
./scanner --git-diff --severity MEDIUM
```

### Hybrid AI Orchestrator Examples

```bash
# Default (safe, sequential) scan of a repo
python3 runner__.py ../../dvja ./scanner

# Scan a subdirectory, creating an 'output/dvja_src' folder
python3 runner__.py ../../dvja/src ./scanner

# Run a faster scan using parallel requests to Claude
python3 runner__.py ../../WebGoat ./scanner --parallel

# Run a scan with verbose debug logging for troubleshooting
python3 runner__.py ../../WebGoat ./scanner --debug

# Filter the static scan results, but still send all files to Claude for full analysis
python3 runner__.py ../../WebGoat ./scanner --severity HIGH
```

---

## 📁 Output Structure (Orchestrator)

The Python orchestrator creates a structured output to keep your results organized:

```
output/
└── <repository_name>/
    ├── static_findings.json  # Results from the Go scanner
    ├── ai_findings.json      # Results from Claude AI
    └── combined_findings.json # Merged and deduplicated results
```

---

## 🎉 Tips for Effective Scanning

1.  **For CI/CD:** Use the standalone `./scanner` with `--exit-high` for fast, free, and automated checks on every commit.
2.  **For Deep Reviews:** Use the `python3 runner__.py` orchestrator for a comprehensive security assessment before a major release or during a security audit.
3.  **Start Focused:** Begin with `--severity HIGH` on the standalone scanner to tackle the most critical issues first.
4.  **Reduce Noise:** Use `--ignore` or a `.scannerignore` file to exclude test files, dependencies, and generated code.
5.  **Trace Findings:** In the `combined_findings.json` file, use the `"source"` field to see whether a vulnerability was found by `"gowasp"` or `"claude"`.

