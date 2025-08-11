
# Smart Code Analyzer ..beta..

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Powered by](https://img.shields.io/badge/Powered%20by-Claude%203.5%20Sonnet-orange.svg)

An AI-powered, multi-stage script for deep, contextual analysis of codebases using the Anthropic Claude 3.5 Sonnet API.
This tool goes beyond simple file-by-file scanning to provide **holistic, synthesized insights** and **optional testing payloads** for both Red and Blue teams.

---

## Overview

Typical static analysis runs on every file, regardless of context — often producing noise.
**Smart Code Analyzer** works differently:

1. **Prioritization** – The AI scans the repo’s structure to find the most relevant files for your query.
2. **Deep Dive** – It runs a targeted file-by-file analysis on only the prioritized subset.
3. **Synthesis** – Findings are aggregated into a **dynamic, context-aware final report**:

   * Security questions → **Threat Model**
   * Performance questions → **Performance Profile**
   * Refactoring questions → **Architectural Review**
4. **Optional Payload Generation** – If enabled, creates **verification** (Red Team) and **defense** (Blue Team) payloads for the top findings.
5. **Optional YAML/YML Mode** – Skip YAML by default to reduce noise. Use `--include-yaml` to analyze YAML/YML files (e.g., CI/CD workflows, Helm charts) when needed.

---

## Key Features

* **Multi-Stage AI Pipeline** – Combines breadth and depth in analysis.
* **Context-Aware Summaries** – Tailored to your question type.
* **Red/Blue Payloads** – Generate test payloads for validation & defense.
* **Multiple Output Formats** – Console, HTML, Markdown.
* **YAML/YML Toggle** – Analyze YAML/YML files only on demand.
* **Verbose & Debug Modes** – Detailed output or raw API responses for dev/debug use.
* **Top-N Control** – Limit the number of findings to focus on critical items.
* **Color Output** – Auto-detected, with `--no-color` override.

---

## Installation

1. **Python 3.8+**
2. **Install dependencies**:

   ```bash
   pip install rich anthropic
   ```
3. **Set your Anthropic API key**:

   ```bash
   export CLAUDE_API_KEY="your_api_key_here"
   ```

---

## Usage

```bash
python3 smart_analyzer.py -h
```

```
usage: smart_analyzer.py [-h] [-v] [--debug]
                         [--format [{console,html,markdown} ...]]
                         [-o OUTPUT] [--no-color]
                         [--top-n TOP_N] [--generate-payloads]
                         [--include-yaml]
                         repo_path [question]

positional arguments:
  repo_path             Path to the repository to analyze
  question              Analysis question (prompts if not provided)

options:
  -h, --help            Show this help message and exit.
  -v, --verbose         Print detailed findings as they are found.
  --debug               Print raw API responses for every call.
  --format [{console,html,markdown} ...]
                        Output format(s).
  -o, --output          Base output filename (suffixes added automatically).
  --no-color            Disable colorized output.
  --top-n TOP_N         Limit summary and payload generation to top N findings.
  --generate-payloads   Generate Red/Blue team payloads for top findings.
  --include-yaml        Include YAML/YML files in analysis (disabled by default).
```

---

## Examples

#### 1. **Basic Interactive Scan**

```bash
python3 smart_analyzer.py /path/to/repo
```

#### 2. **Security Threat Model + Payloads**

```bash
python3 smart_analyzer.py /path/to/app \
  "Threat model for injection & auth vulnerabilities" \
  --generate-payloads --top-n 3
```

#### 3. **Performance Profile with Verbose Output**

```bash
python3 smart_analyzer.py /path/to/app \
  "Find performance bottlenecks" -v
```

#### 4. **Architectural Review to HTML & Markdown**

```bash
python3 smart_analyzer.py /path/to/app \
  "Review architecture" --format html markdown --output review
```

#### 5. **Including YAML Files in the Scan**

```bash
python3 smart_analyzer.py /path/to/app \
  "Review GitHub Actions for security risks" --include-yaml
```

---

## Notes on YAML/YML Analysis

* **By default**, `.yaml` and `.yml` files are **excluded** to avoid irrelevant CI/CD noise.
* Use `--include-yaml` when:

  * Reviewing **GitHub Actions**, **GitLab CI**, **Helm charts**, **Kubernetes manifests**.
  * Performing **infrastructure-as-code** audits.

##
##
