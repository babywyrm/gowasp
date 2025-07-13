# OWASP Scanner (Beta)

The OWASP Scanner is a lightweight, multi-language static analysis tool that detects OWASP Top 10 security issues—and more—in your source code.  
It supports Go, JS, Python, Java, PHP, HTML, and can output in text, JSON, or Markdown. Integrates with CI/CD, fails on HIGH severity, and can comment on GitHub PRs.

---

## Features

- Multi-language scanning (Go, JS, Python, Java, HTML, PHP…)  
- OWASP Top 10 rule set with CRITICAL/HIGH/MEDIUM/LOW severities  
- Custom rules via JSON:  
  - **rules_core.json** (OWASP‐focused)  
  - **rules_infra.json** (infra, cloud & container checks)  
- `--rules` accepts comma-separated list of JSON files  
- Git diff scanning (`--git-diff`), ignore globs (`--ignore`)  
- Output: text, JSON, Markdown (`--output`)  
- Remediation hints (`--verbose`)  
- CI/CD safe: `--exit-high`  
- GitHub PR comments (`--github-pr`)  
- Handles large files (10 MB buffer, skips lines >100 KB)  

---

## Installation

```bash
git clone https://github.com/babywyrm/gowasp.git
cd gowasp/gowasp

# (Optional) generate default rules.json
go run gen_rule_json.go rules.go > rules.json

# Build
go build -o scanner gowasp.go
```

---

## Usage

```
./scanner --help
```

| Flag         | Description                                     |
| ------------ | ----------------------------------------------- |
| `--dir`      | Directory to scan (default `.`)                 |
| `--rules`    | Comma-separated JSON rule files                 |
| `--severity` | Minimum severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `--ignore`   | Comma-separated glob patterns to skip           |
| `--git-diff` | Scan only files changed in last commit          |
| `--output`   | `text`, `json`, `markdown`                      |
| `--verbose`  | Show remediation advice                         |
| `--exit-high`| Exit code 1 if any HIGH found                   |
| `--github-pr`| Post Markdown report to GitHub PR               |
| `--debug`    | Enable internal logging                         |

### Multiple Rule Files

Point at both core and infra rule sets:

```bash
./scanner \
  --rules=rules/rules_core.json,rules/rules_infra.json \
  --dir ./src \
  --severity HIGH \
  --output markdown
```

---

## Examples

### Basic

```bash
./scanner --dir . --output text
./scanner --dir . --severity HIGH --output markdown
./scanner --git-diff --severity MEDIUM --output text
```

### Custom Rules

```bash
./scanner --rules=rules/custom_rules.json --dir ./src --severity CRITICAL
```

### DVWA

```bash
# Noisy: full DVWA (~178 findings)
./scanner --dir ../../dvwa --severity MEDIUM --output markdown

# Better: skip demos (~83 findings)
./scanner \
  --dir ../../dvwa --severity MEDIUM --output markdown \
  --ignore "vendor,node_modules,**/help/**,**/source/**,setup.php,test*.php,**/tests/**"

# Best: only app code (11 findings)
./scanner \
  --dir ../../dvwa/vulnerabilities/api \
  --severity HIGH --output markdown
```

### WebGoat

```bash
# Noisy: full WebGoat (~391 findings)
./scanner --dir ../../WebGoat --severity HIGH --output markdown

# Better: skip tests/assets (~100 findings)
./scanner \
  --dir ../../WebGoat --severity HIGH --output markdown \
  --ignore "src/it/**,src/test/**,**/static/**,**/resources/**"

# Best: core lessons (~20 findings)
./scanner \
  --dir ../../WebGoat/src/main/java/org/owasp/webgoat/lessons \
  --severity HIGH --output markdown
```

### Infra Rules Only

```bash
./scanner \
  --rules=rules/rules_infra.json \
  --dir ./deploy \
  --severity HIGH --output markdown
```

### Combined Core + Infra

```bash
./scanner \
  --rules=rules/rules_core.json,rules/rules_infra.json \
  --dir ./deploy \
  --severity HIGH --output markdown
```

---

## Using `.scannerignore`

Create `.scannerignore` in project root:

```
vendor/**
node_modules/**
dist/**
build/**
public/**
**/tests/**
**/help/**
**/source/**
```

Then run:

```bash
./scanner --ignore= --dir . --severity HIGH --output markdown
```

---

## CI/CD Integration

**Exit on HIGH**:

```bash
./scanner --dir . --severity HIGH --exit-high
```

**GitHub Actions**:

```yaml
- name: Static Analysis
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

---

## Tips

1. Start with `--severity HIGH`  
2. Use `--ignore` or `.scannerignore` to reduce noise  
3. Target specific dirs (`--dir`) for focused scans  
4. Combine with `--git-diff` in dev workflows  
5. Split rules into core/infra for modularity  

