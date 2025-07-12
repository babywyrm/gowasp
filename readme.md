
# OWASP Scanner (Beta)

The OWASP Scanner is a lightweight, multi-language static analysis tool that detects common OWASP Top 10 security issues in your source code.  
It supports Go, JavaScript, Python, Java, PHP, HTML, and more.

It can output results in plain text, JSON, or Markdown formats, integrate with CI/CD (failing builds on HIGH severity), and even post scan results as comments on GitHub pull requests.

---

## Features

- Multi-language scanning (Go, JS, Python, Java, HTML, PHP…)  
- OWASP Top 10 rule set (Injection, Auth failures, Insecure configs, etc.)  
- Load custom rules via `rules.json` (see `--rules`)  
- Git diff scanning (`--git-diff`), ignore globs (`--ignore`)  
- Output formats: `text`, `json`, `markdown`  
- Remediation advice with `--verbose`  
- CI/CD-safe: `--exit-high` to fail builds  
- GitHub PR comment support with `--github-pr`

---

## Installation

1. **Clone the project**
   ```bash
   git clone https://github.com/babywyrm/gowasp.git
   cd gowasp/gowasp
````

2. **(Optional) Generate `rules.json` from built-ins**

   ```bash
   go run gen_rule_json.go rules.go > rules.json
   ```

3. **Build the binary**

   ```bash
   go build -o scanner gowasp.go
   ```

---

## Usage

Run `./scanner --help` for full flag details.

| Flag          | Description                               |
| ------------- | ----------------------------------------- |
| `--dir`       | Directory to scan (default: `.`)          |
| `--rules`     | Path to custom `rules.json`               |
| `--ignore`    | Comma-separated glob patterns to skip     |
| `--git-diff`  | Scan only files changed in last commit    |
| `--output`    | Output format: `text`, `json`, `markdown` |
| `--verbose`   | Show remediation advice in output         |
| `--exit-high` | Exit code 1 if any HIGH severity is found |
| `--github-pr` | Post Markdown report to GitHub PR comment |
| `--debug`     | Enable internal logging                   |

---

### 🔍 Basic Scan

```bash
./scanner --dir . --output text
```

### 📄 Use External Rules

```bash
./scanner --rules=rules.json --dir=./src --output=markdown --verbose
```

### 🔃 Scan Only Changed Files

```bash
./scanner --rules=rules.json --git-diff --output=markdown
```

### 💾 Save as JSON

```bash
./scanner --dir . --output json --verbose > findings.json
```

### 🚨 Fail Build on HIGH Findings

```bash
./scanner --dir . --exit-high
```

---

## 🧪 GitHub PR Comment Integration

Set the following environment variables in your GitHub Actions or CI/CD pipeline:

```bash
export GITHUB_REPOSITORY="babywyrm/gowasp"
export GITHUB_PR_NUMBER="42"
export GITHUB_TOKEN="ghp_..."  # must have `repo` scope
```

Then run:

```bash
./scanner --rules=rules.json --output markdown --github-pr --verbose
```

---

## Output Examples

### Go Project (text)

```
[HIGH] main.go:45 – Go FormValue (r.FormValue("username"))
    ▶ Unvalidated form input
    ⚑ Validate & sanitize all form inputs.
```

### Python Project (JSON)

```json
[
  {
    "file": "app.py",
    "line": 78,
    "rule_name": "Hardcoded Password",
    "match": "password = \"secret123\"",
    "severity": "HIGH",
    "category": "A02",
    "timestamp": "2025-07-12T16:45:00Z"
  }
]
```

### JavaScript Project (Markdown)

```markdown
### 🔍 Static Analysis Findings

| File       | Line | Rule               | Match                     | Severity | OWASP |
|------------|------|--------------------|---------------------------|----------|-------|
| server.js  | 102  | Node req.query     | `req.query.name`          | **HIGH** | A01   |
| app.js     |  88  | Inline JS Handler  | `onClick="doSomething()"` | **MEDIUM** | A07   |
```

