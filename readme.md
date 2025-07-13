# GOWASP & More Extended Scanner (..Beta..) 🎉

The OWASP Scanner is a lightweight, multi-language static analysis tool that detects OWASP Top 10 security issues—and more—in your source code.

It supports Go, JS, Python, Java, PHP, HTML, and can output in text, JSON, or Markdown. 

Integrates with CI/CD, fails on HIGH severity, and can comment on GitHub PRs.

---

## 🚀 Features

- Multi-language scanning (Go, JS, Python, Java, HTML, PHP…)  
- OWASP Top 10 rule set with CRITICAL/HIGH/MEDIUM/LOW severities  
- Custom rules via JSON:  
  - **rules_core.json** (OWASP‐focused)  
  - **rules_infra.json** (infra, cloud & container checks)  
- `--rules` accepts comma-separated rule files  
- Git diff scanning (`--git-diff`), ignore globs (`--ignore`)  
- Output: `text`, `json`, `markdown` (`--output`)  
- Remediation hints (`--verbose`)  
- CI/CD safe: `--exit-high`  
- GitHub PR comments (`--github-pr`)  
- Handles large files (10 MB buffer, skips lines >100 KB)  

---

## 🔧 Installation

```bash
git clone https://github.com/babywyrm/gowasp.git
cd gowasp/gowasp

# Optional: generate default rules.json
go run gen_rule_json.go rules.go > rules.json

# Build scanner
go build -o scanner gowasp.go
```

---

## 📖 Usage

```bash
./scanner --help
```

| Flag         | Description                                      |
| ------------ | ------------------------------------------------ |
| `--dir`      | Directory to scan (default `.`)                  |
| `--rules`    | Comma-separated JSON rule files                  |
| `--severity` | Minimum severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `--ignore`   | Comma-separated glob patterns to skip            |
| `--git-diff` | Scan only files changed in last commit           |
| `--output`   | `text`, `json`, `markdown`                       |
| `--verbose`  | Show remediation advice                          |
| `--exit-high`| Exit code 1 if any HIGH severity is found        |
| `--github-pr`| Post Markdown report to GitHub PR                |
| `--debug`    | Enable internal logging                          |

### Multiple Rule Files

```bash
./scanner \
  --rules=rules/rules_core.json,rules/rules_infra.json \
  --dir=./src \
  --severity HIGH \
  --output markdown
```

---

## 🎯 Basic Examples

```bash
# Quick text scan
./scanner --dir . --output text

# Markdown, HIGH severity only
./scanner --dir . --severity HIGH --output markdown

# JSON export for dashboards
./scanner --dir . --output json > findings.json

# Only scan changed files
./scanner --git-diff --severity MEDIUM --output text
```

---

## 🛠 Advanced Workflows

### 🔍 Reduce Noise by Ignoring Patterns

```bash
# Skip vendor, tests, built assets
./scanner --dir . --severity HIGH \
  --ignore "vendor/**,**/tests/**,dist/**,build/**"
```

### 💾 Export & Filter

```bash
# Full JSON, then JQ filter Critical infra rules
./scanner --rules=rules_core.json,rules_infra.json \
  --dir . --output json > all.json

jq '[.[] | select(.rule_name | IN( (input | split("\n")) ))]' \
   infra_names.txt all.json > infra_findings.json
```

### 🔗 CI/CD Integration

```bash
# Fail build on any HIGH
./scanner --dir . --severity HIGH --exit-high

# GitHub Actions step
- name: Security Scan
  run: |
    ./scanner \
      --rules=rules/rules_core.json,rules/rules_infra.json \
      --dir . \
      --severity HIGH \
      --output markdown \
      --github-pr \
      --verbose
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    GITHUB_REPOSITORY: ${{ github.repository }}
    GITHUB_PR_NUMBER: ${{ github.event.number }}
```

### 🏗️ Release Audit

```bash
# Full code scan
./scanner --dir . --severity MEDIUM --output json > report.json

# Convert to HTML (example)
jq -r '.[] | "<tr><td>\(.file)</td><td>\(.line)</td><td>\(.rule_name)</td><td>\(.severity)</td></tr>"' report.json \
  | sed -e '1i\<table><tr><th>File</th><th>Line</th><th>Rule</th><th>Severity</th>' -e '$a\</table>' \
  > security-report.html
```

---

## 🔍 **Examples: DVWA**

```bash
# Noisy: full DVWA (~178 findings)
./scanner --dir ../../dvwa --severity MEDIUM --output markdown

# Better: skip demo/help files (~83 findings)
./scanner \
  --dir ../../dvwa --severity MEDIUM \
  --ignore "vendor,node_modules,**/help/**,**/source/**,setup.php,test*.php,**/tests/**" \
  --output markdown

# Best: app code only (11 findings)
./scanner \
  --dir ../../dvwa/vulnerabilities/api \
  --severity HIGH --output markdown
```

---

## 🔍 **Examples: WebGoat**

```bash
# Noisy: full WebGoat (~391 findings)
./scanner --dir ../../WebGoat --severity HIGH --output markdown

# Better: skip tests/assets (~100 findings)
./scanner \
  --dir ../../WebGoat --severity HIGH \
  --ignore "src/it/**,src/test/**,**/static/**,**/resources/**" \
  --output markdown

# Best: core lessons (~20 findings)
./scanner \
  --dir ../../WebGoat/src/main/java/org/owasp/webgoat/lessons \
  --severity HIGH --output markdown
```

---

## 📁 Using `.scannerignore`

```bash
# Project root .scannerignore
vendor/**
node_modules/**
dist/**
build/**
public/**
**/tests/**
**/help/**
**/source/**
```

Then:

```bash
./scanner --dir . --severity HIGH --output markdown
```

---

## 🎉 Tips for Effective Scanning

1. Start with `--severity HIGH` to focus on critical issues  
2. Use `--ignore` or `.scannerignore` to cut down noise  
3. Target specific directories (`--dir`) for focused scans  
4. Combine with `--git-diff` in your dev workflow  
5. Split rules into core/infra for modularity  
6. Export JSON for dashboards or integration with other tools  

##
##

