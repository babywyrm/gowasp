
# Smart Code Analyzer

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Powered by](https://img.shields.io/badge/Powered%20by-Claude%203.5%20Sonnet-orange.svg)

An AI-powered, multi-stage script for deep, contextual analysis of codebases using the Anthropic Claude 3.5 Sonnet API. This tool moves beyond simple file-by-file scanning to provide holistic, synthesized insights.

## Overview

Standard static analysis often misses the big picture by looking at files in isolation. This tool solves that problem by mimicking how a human expert works, using a **three-stage analysis pipeline**:

1.  **Prioritization:** The AI first performs a high-level scan of the repository's file structure to identify the most critical files relevant to your question. This focuses the deep analysis on what matters most.
2.  **Deep Dive:** It then conducts a detailed, file-by-file analysis on this prioritized subset of files, extracting specific findings and recommendations.
3.  **Synthesis:** Finally, it aggregates all the raw findings and sends them back to the AI in a final pass, asking it to act as a principal architect. The result is a holistic, executive-level summary that identifies overarching themes, threat vectors, and a strategic remediation plan.

This approach provides both granular, file-specific details and a high-level, synthesized understanding of your codebase.

## Features

-   **Multi-Stage Analysis Pipeline:** Ensures the analysis is both focused and holistic.
-   **AI-Driven Prioritization:** Intelligently focuses deep analysis on the most relevant parts of your codebase, saving time and API costs.
-   **AI-Driven Synthesis:** Generates a high-level executive summary, threat model, and strategic plan from low-level findings.
-   **Verbose & Debug Modes:** Use `-v` for real-time findings and `--debug` to see the raw, unparsed API responses for troubleshooting.
-   **Configurable Summaries:** Use the `--top-n` flag to control the number of items in the final summary tables.
-   **Multiple Report Formats:** Output to the console, HTML, Markdown, and JSON.
-   **Automatic Color Detection:** Uses rich, colorized output in supported terminals, with a `--no-color` override.
-   **Interactive & CI Friendly:** Works interactively by prompting for a question or can be fully automated by providing the question as a command-line argument.

## Requirements

1.  **Python 3.8+**
2.  **Required Libraries:** `rich` and `anthropic`. Install them with:
    ```bash
    pip install -r requirements.txt
    ```
3.  **API Key:** You must have your Anthropic API key set as an environment variable.
    ```bash
    export CLAUDE_API_KEY="your_api_key_here"
    ```

*(Note: A `requirements.txt` file for this project would contain:)*
```
rich
anthropic
```

## Usage

The script takes a repository path and a question as input. If the question is omitted, the script will prompt for it interactively.

```bash
python3 smart_analyzer.py -h
```
```
usage: smart_analyzer.py [-h] [--verbose] [--debug] [--format [{console,html,markdown} ...]] [--output OUTPUT] [--no-color] [--top-n TOP_N] repo_path [question]

A multi-stage 'lite' dynamic code analyzer using Claude.

positional arguments:
  repo_path             Path to the repository to analyze
  question              Analysis question (will prompt if not provided)

options:
  -h, --help            show this help message and exit
  --verbose, -v         Print detailed insights for each file as they are found.
  --debug               Print raw API responses for every call, regardless of parsing success.
  --format [{console,html,markdown} ...]
                        One or more output formats.
  --output, -o OUTPUT   Base output file path (e.g., "report"). Suffix is ignored.
  --no-color            Disable colorized output in the terminal.
  --top-n TOP_N         Number of items to show in summary tables.
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
Enter your question: How can we improve error handling and logging in this project?
```

#### 2. Detailed Security Threat Model (Verbose Mode)

Provide a specific security question and use the `-v` flag to see detailed findings for each file as they are discovered.

```bash
python3 smart_analyzer.py /path/to/vulnerable-app "Threat model this application for injection vulnerabilities and insecure authentication patterns" -v
```
This will run the full pipeline and also print real-time details during the "Deep Dive" stage, giving you immediate feedback.

#### 3. Generate Multiple Reports (HTML & Markdown)

Ask a high-level architectural question and generate both an HTML and a Markdown file from the results.

```bash
python3 smart_analyzer.py /path/to/your/repo "What are the main architectural patterns and where are the potential design flaws?" --format html markdown --output arch_review
```
This will create `arch_review.html` and `arch_review.md`.

#### 4. Debugging API Responses

If you are developing the script or the prompts, the `--debug` flag is invaluable. It will print the full, raw JSON response from the API for every call.

```bash
python3 smart_analyzer.py /path/to/your/repo "Find hardcoded secrets" --debug
```

## How It Works: The 3-Stage Pipeline

1.  **Stage 1: Prioritization**
    -   The script scans all filenames in your repository.
    -   It sends this list to Claude with your question and asks: *"Which of these files are most important for answering this question?"*
    -   This allows the AI to focus its expensive, deep analysis on high-value targets like `UserService`, `LoginController`, or `PaymentProcessor`.

2.  **Stage 2: Deep Dive Analysis**
    -   The script iterates through the prioritized list of files from Stage 1.
    -   For each file, it sends the full code content to Claude and asks for specific, low-level findings (e.g., "SQL Injection on line 45," "Missing null check on line 82").
    -   This is where the raw data for the analysis is generated.

3.  **Stage 3: Synthesis**
    -   All the raw findings from Stage 2 are collected into a single list.
    -   This list is sent back to Claude in a final, high-level prompt that asks it to act as a principal architect.
    -   The prompt instructs the AI to ignore the low-level details and instead **synthesize** the findings into an executive summary, identify the top 3-5 overarching threat vectors or patterns, and propose a strategic remediation plan. This final step is what produces the high-quality, human-like summary.

## License

This project is licensed under the MIT License.
