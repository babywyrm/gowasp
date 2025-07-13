# OWASP Scanner (Beta)

The OWASP Scanner is a lightweight, multi-language static analysis tool that detects common OWASP Top 10 security issues in your source code.  
It supports Go, JavaScript, Python, Java, PHP, HTML, and more.

It can output results in plain text, JSON, or Markdown formats, integrate with CI/CD (failing builds on HIGH severity), and even post scan results as comments on GitHub pull requests.

---

## Features

- Multi-language scanning (Go, JS, Python, Java, HTML, PHP…)  
- OWASP Top 10 rule set (Injection, Auth failures, Insecure configs, etc.)  
- Severity filtering with `--severity` (CRITICAL, HIGH, MEDIUM, LOW)
- Load custom rules via `rules.json` (see `--rules`)  
- Git diff scanning (`--git-diff`), ignore globs (`--ignore`)  
- Output formats: `text`, `json`, `markdown`  
- Remediation advice with `--verbose`  
- CI/CD-safe: `--exit-high` to fail builds  
- GitHub PR comment support with `--github-pr`
- Large file handling (up to 10MB lines, skips 100KB+ lines)

---

## Installation

1. **Clone the project**
   ```bash
   git clone https://github.com/babywyrm/gowasp.git
   cd gowasp/gowasp
   ```

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

| Flag          | Description                                      |
| ------------- | ------------------------------------------------ |
| `--dir`       | Directory to scan (default: `.`)                |
| `--rules`     | Path to custom `rules.json`                     |
| `--severity`  | Minimum severity to show (CRITICAL, HIGH, MEDIUM, LOW) |
| `--ignore`    | Comma-separated glob patterns to skip           |
| `--git-diff`  | Scan only files changed in last commit          |
| `--output`    | Output format: `text`, `json`, `markdown`       |
| `--verbose`   | Show remediation advice in output               |
| `--exit-high` | Exit code 1 if any HIGH severity is found       |
| `--github-pr` | Post Markdown report to GitHub PR comment       |
| `--debug`     | Enable internal logging                         |

---

## Basic Examples

### 🔍 Quick Scan
```bash
./scanner --dir . --output text
```

### 🎯 High Severity Only
```bash
./scanner --dir . --severity HIGH --output markdown
```

### 📊 Medium and Above with Summary
```bash
./scanner --dir . --severity MEDIUM --output markdown --verbose
```

### 🔃 Scan Only Git Changes
```bash
./scanner --git-diff --severity HIGH --output markdown
```

---

## Advanced Scanning Strategies

### 🎯 Focus on Application Code (Reduce Noise)

**Scan specific directories:**
```bash
# Scan just API/application code
./scanner --dir ./src/api --severity HIGH --output markdown

# Skip test and vendor files
./scanner --dir . --severity HIGH --ignore "vendor/**,**/tests/**,**/test/**,node_modules/**"
```

** Yes, Examples: DVWA Scanning 
```bash
# Noisy: Full DVWA scan (178 findings)
./scanner --dir ../../dvwa --severity MEDIUM --output markdown

# Better: Skip demo/help files (83 findings)  
./scanner --dir ../../dvwa --severity MEDIUM --output markdown \
  --ignore "vendor,node_modules,**/help/**,**/source/**,setup.php,test*.php,**/tests/**"

# Best: Focus on real application code (11 findings)
./scanner --dir ../../dvwa/vulnerabilities/api --severity HIGH --output markdown


** Another Example: WebGoat Scanning 

```bash
# Noisy: Full WebGoat scan (391 findings)
./scanner --dir ../../WebGoat --severity HIGH --output markdown

# Better: Skip integration tests, unit tests & static assets (~100 findings)
./scanner --dir ../../WebGoat --severity HIGH --output markdown \
  --ignore "src/it/**,src/test/**,**/static/**,**/resources/**"

# Best: Focus on core lesson code (~20 findings)
./scanner --dir ../../WebGoat/src/main/java/org/owasp/webgoat/lessons \
  --severity HIGH --output markdown
```


```

### 📁 Using .scannerignore File

Create a `.scannerignore` file in your project root:
```bash
# Framework/vendor files
vendor/**
node_modules/**
**/tests/**
**/test/**

# Generated files
dist/**
build/**
public/**

# Demo/help files  
**/help/**
**/source/**
**/docs/**
setup.php
install.php
```

Then scan normally:
```bash
./scanner --dir . --severity HIGH --output markdown
```

### 🏗️ CI/CD Integration

**Fail builds on HIGH findings:**
```bash
./scanner --dir . --severity HIGH --exit-high
```

**GitHub Actions example:**
```yaml
- name: Security Scan
  run: |
    ./scanner --dir . --severity HIGH --output markdown --github-pr --verbose
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    GITHUB_REPOSITORY: ${{ github.repository }}
    GITHUB_PR_NUMBER: ${{ github.event.number }}
```

---

## Real-World Examples

### 🎯 Production Application Scan
```bash
# Focus on source code, ignore noise
./scanner --dir ./src --severity HIGH --output markdown \
  --ignore "vendor/**,node_modules/**,**/tests/**,dist/**" \
  --verbose
```

### 🔍 Development Workflow
```bash
# Quick check of changed files
./scanner --git-diff --severity MEDIUM --output text

# Detailed analysis before commit
./scanner --git-diff --severity HIGH --output markdown --verbose
```

### 📈 Security Review
```bash
# Complete scan with all findings
./scanner --dir . --severity LOW --output json > security-report.json

# Executive summary
./scanner --dir . --severity HIGH --output markdown --verbose
```

---

## Sample Output

### Real Application (API Focus)
````markdown
### 🔍 Static Analysis Findings

| File | Line | Rule | Match | Severity | OWASP |
|------|------|------|-------|----------|-------|
| `src/Login.php` | 10 | API Key | `SECRET = "12345"` | **HIGH** | A02 |
| `src/HealthController.php` | 88 | Command Exec | `exec (` | **HIGH** | A03 |
| `js/auth.js` | 43 | innerHTML | `.innerHTML =` | **HIGH** | A07 |

**Severity Summary**
- **HIGH**: 3

**OWASP Category Summary**  
- **A02**: 1
- **A03**: 1
- **A07**: 1
```

### Noisy Scan (Too Many False Positives)
```bash
# This will find 178 findings, mostly noise:
./scanner --dir ../../dvwa --severity LOW --output text

# Better approach:
./scanner --dir ../../dvwa/vulnerabilities/api --severity HIGH --output markdown
# Results: 11 focused, actionable findings
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

## Tips for Effective Scanning

1. **Start with HIGH severity** to avoid noise
2. **Use directory targeting** (`--dir ./src/api`) for focused results  
3. **Ignore test/vendor files** to reduce false positives
4. **Use .scannerignore** for consistent exclusions across team
5. **Combine with git-diff** for efficient development workflow
6. **Tune rules.json** for your specific tech stack

---

## Custom Rules

Create a `rules.json` file to override built-in rules:

```json
[
  {
    "name": "Hardcoded API Key",
    "pattern": "(?i)(api[_-]?key|secret)[\"'\\s]*[:=][\"'\\s]*[a-zA-Z0-9]{16,}",
    "severity": "CRITICAL",
    "category": "A02",
    "description": "Hardcoded API key detected",
    "remediation": "Move API keys to environment variables or secure vault"
  }
]
```

Use with:
```bash
./scanner --rules rules.json --dir . --severity CRITICAL
```
