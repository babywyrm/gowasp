
# Smart Code Analyzer  ..beta..

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Powered by](https://img.shields.io/badge/Powered%20by-Claude%203.5%20Sonnet-orange.svg)

An AI-powered, multi-stage script for deep, contextual analysis of codebases using the Anthropic Claude 3.5 Sonnet API. This tool moves beyond simple file-by-file scanning to provide holistic, synthesized insights and actionable testing payloads.

## Overview

Standard static analysis often misses the big picture by looking at files in isolation. This tool solves that problem by mimicking how a human expert works, using a **multi-stage analysis pipeline**:

1.  **Prioritization:** The AI first performs a high-level scan of the repository's file structure to identify the most critical files relevant to your question. This focuses the deep analysis on what matters most.
2.  **Deep Dive:** It then conducts a detailed, file-by-file analysis on this prioritized subset of files, extracting specific findings and recommendations.
3.  **Synthesis:** It aggregates all the raw findings and sends them back to the AI in a final pass, asking it to act as a principal architect. The AI's summary is **dynamically tailored** to your question, providing a threat model for security queries or a performance profile for optimization queries.
4.  **(Optional) Payload Generation:** If requested, the script performs a final pass on the top findings to generate example payloads for both vulnerability verification (Red Team) and defense testing (Blue Team).

This approach provides granular details, a high-level strategic summary, and actionable testing materials all in one run.

## Features

-   **Multi-Stage Analysis Pipeline:** Ensures the analysis is both focused and holistic.
-   **AI-Driven Prioritization:** Intelligently focuses deep analysis on the most relevant parts of your codebase.
-   **Dynamic AI Synthesis:** The final summary adapts to your question, generating a **Threat Model** for security questions, a **Performance Profile** for optimization questions, or an **Architectural Review** for refactoring questions.
-   **Red/Blue Team Payload Generation:** An optional `--generate-payloads` flag creates example payloads for top findings, useful for both vulnerability verification and defense testing.
-   **Verbose & Debug Modes:** Use `-v` for real-time findings and `--debug` to see the raw, unparsed API responses for troubleshooting.
-   **Configurable Summaries:** Use the `--top-n` flag to control the number of items in summary tables and for payload generation.
-   **Multiple Report Formats:** Output to the console, HTML, and Markdown.
-   **Automatic Color Detection:** Uses rich, colorized output in supported terminals, with a `--no-color` override.

## Requirements

1.  **Python 3.8+**
2.  **Required Libraries:** `rich` and `anthropic`. Install them with:
    ```bash
    pip install rich anthropic
    ```
3.  **API Key:** You must have your Anthropic API key set as an environment variable.
    ```bash
    export CLAUDE_API_KEY="your_api_key_here"
    ```

## Usage

The script takes a repository path and a question as input. If the question is omitted, the script will prompt for it interactively.

```bash
python3 smart_analyzer.py -h
```
```
usage: smart_analyzer.py [-h] [-v] [--debug] [--format [{console,html,markdown} ...]] [-o OUTPUT] [--no-color] [--top-n TOP_N] [--generate-payloads] repo_path [question]

A multi-stage AI code analyzer.

positional arguments:
  repo_path             Path to the repository to analyze
  question              Analysis question (prompts if not provided)

options:
  -h, --help            show this help message and exit
  -v, --verbose         Print detailed insights for each file as they are found.
  --debug               Print raw API responses for every call.
  --format [{console,html,markdown} ...]
                        One or more output formats.
  -o, --output          Base output file path (e.g., "report"). Suffix is ignored.
  --no-color            Disable colorized output.
  --top-n TOP_N         Number of items for summary tables and payload generation.
  --generate-payloads   Generate example Red/Blue team payloads for top findings.
```

---

## Demos & Examples

#### 1. Basic Interactive Scan

This is the simplest way to run the analyzer. It will scan the repository and then prompt you to enter your analysis question.

```bash
python3 smart_analyzer.py /path/to/your/repo
```
```
What would you like to analyze about this codebase?
Examples: 'Find security vulnerabilities', 'Suggest performance improvements', 'How can I refactor this code?'
Enter your question: How can we improve error handling and logging in this project?
```

#### 2. Security Threat Model with Payload Generation

This is the most powerful security feature. It performs a full threat model and then generates example payloads for the top 3 most critical findings.

```bash
python3 smart_analyzer.py /path/to/vulnerable-app "Threat model this app for injection and auth vulnerabilities" --generate-payloads --top-n 3
```

#### 3. Performance Analysis with Verbose Output

Ask a performance-related question to get a dynamically generated "Performance Profile" in the final synthesis. Use `-v` to see potential bottlenecks as they are found.

```bash
python3 smart_analyzer.py /path/to/your/repo "Find performance bottlenecks and suggest optimizations" -v
```

#### 4. Generate HTML & Markdown Reports for Refactoring

Ask a high-level architectural question and generate both an HTML and a Markdown file from the results.

```bash
python3 smart_analyzer.py /path/to/your/repo "What are the main architectural patterns and where are the potential design flaws?" --format html markdown --output arch_review
```
This will create `arch_review.html` and `arch_review.md`.

#### 5. Debugging API Responses

If you are developing the script or the prompts, the `--debug` flag is invaluable. It will print the full, raw JSON response from the API for every call.

```bash
python3 smart_analyzer.py /path/to/your/repo "Find hardcoded secrets" --debug
```
