package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
)

// --- Core Data Structures ---

// Rule defines a single static analysis rule.
type Rule struct {
	Name        string
	Regex       string
	Pattern     *regexp.Regexp
	Severity    string
	Category    string
	Description string
	Remediation string
}

// Finding represents a single vulnerability discovered in a file.
type Finding struct {
	File      string    `json:"file"`
	Line      int       `json:"line"`
	RuleName  string    `json:"rule_name"`
	Match     string    `json:"match"`
	Severity  string    `json:"severity"`
	Category  string    `json:"category"`
	Timestamp time.Time `json:"timestamp"`
}

// --- Global Variables and Constants ---

var rules []Rule
var ruleMap = map[string]Rule{}

var supportedExtensions = map[string]bool{
	".go": true, ".js": true, ".py": true, ".java": true, ".html": true, ".php": true,
}

// severityLevels provides a numeric weight for sorting and filtering.
var severityLevels = map[string]int{
	"CRITICAL": 4,
	"HIGH":     3,
	"MEDIUM":   2,
	"LOW":      1,
}

// --- Rule Loading and Management ---

// InitRules defines the default, built-in security rules as a fallback.
func InitRules() []Rule {
	return []Rule{
		{
			Name:        "HardcodedPassword",
			Regex:       `(?i)password\s*=\s*['"].+['"]`,
			Pattern:     regexp.MustCompile(`(?i)password\s*=\s*['"].+['"]`),
			Severity:    "HIGH",
			Category:    "A02",
			Description: "Possible hardcoded password",
			Remediation: "Remove or secure the credential via secrets manager or env var",
		},
	}
}

// loadRulesFromFile parses a JSON file into a slice of Rule structs.
func loadRulesFromFile(path string) ([]Rule, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var jr []struct {
		Name        string `json:"name"`
		Pattern     string `json:"pattern"`
		Severity    string `json:"severity"`
		Category    string `json:"category"`
		Description string `json:"description"`
		Remediation string `json:"remediation"`
	}
	if err := json.Unmarshal(data, &jr); err != nil {
		return nil, fmt.Errorf("invalid JSON in %s: %w", path, err)
	}
	out := make([]Rule, len(jr))
	for i, r := range jr {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to compile regex for rule %q (index %d) in %s: %v",
				r.Name, i, path, err,
			)
		}
		out[i] = Rule{
			Name:        r.Name,
			Regex:       r.Pattern,
			Pattern:     re,
			Severity:    r.Severity,
			Category:    r.Category,
			Description: r.Description,
			Remediation: r.Remediation,
		}
	}
	return out, nil
}

// init populates the global ruleMap with the initial set of built-in rules.
func init() {
	ruleMap = make(map[string]Rule)
	rules = InitRules()
	for _, r := range rules {
		ruleMap[r.Name] = r
	}
}

// --- Filtering and Utility Functions ---

// meetsSeverityThreshold checks if a finding's severity is at or above the minimum threshold.
func meetsSeverityThreshold(findingSeverity, minSeverity string) bool {
	if minSeverity == "" {
		return true
	}
	fLvl, ok := severityLevels[findingSeverity]
	if !ok {
		return true
	}
	mLvl, ok := severityLevels[minSeverity]
	if !ok {
		return true
	}
	return fLvl >= mLvl
}

// filterBySeverity returns a new slice of findings that meet the minimum severity.
func filterBySeverity(findings []Finding, minSeverity string) []Finding {
	if minSeverity == "" {
		return findings
	}
	var out []Finding
	for _, f := range findings {
		if meetsSeverityThreshold(f.Severity, minSeverity) {
			out = append(out, f)
		}
	}
	return out
}

// runCommand executes an external command and returns its combined output.
func runCommand(ctx context.Context, cmd string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, cmd, args...)
	out, err := c.CombinedOutput()
	return string(out), err
}

// getGitChangedFiles returns a list of files changed in the last git commit.
func getGitChangedFiles(ctx context.Context) ([]string, error) {
	out, err := runCommand(ctx, "git", "diff", "--name-only", "HEAD~1")
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(out), "\n"), nil
}

// loadIgnorePatterns reads ignore patterns from a flag and the .scannerignore file.
func loadIgnorePatterns(ignoreFlag string) ([]string, error) {
	var pats []string
	if ignoreFlag != "" {
		pats = append(pats, strings.Split(ignoreFlag, ",")...)
	}
	f, err := os.Open(".scannerignore")
	if err != nil {
		if os.IsNotExist(err) {
			return pats, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			pats = append(pats, l)
		}
	}
	return pats, sc.Err()
}

// shouldIgnore checks if a given file path matches any of the ignore patterns.
func shouldIgnore(path string, patterns []string) bool {
	for _, pat := range patterns {
		if ok, _ := doublestar.PathMatch(pat, path); ok {
			return true
		}
	}
	return false
}

// --- Core Scanning Logic ---

// scanFile reads a single file line-by-line and applies all loaded rules.
func scanFile(path string, debug bool) ([]Finding, error) {
	if debug {
		log.Printf("Scanning file: %s", path)
	}
	var out []Finding
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	const maxCap = 10 * 1024 * 1024
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, maxCap)

	ln := 0
	for sc.Scan() {
		ln++
		txt := sc.Text()
		if len(txt) > 100000 {
			if debug {
				log.Printf("Skipping long line %d in %s len=%d", ln, path, len(txt))
			}
			continue
		}
		for _, r := range rules {
			if r.Pattern.MatchString(txt) {
				m := r.Pattern.FindString(txt)
				if len(m) > 80 {
					m = m[:80] + "..."
				}
				out = append(out, Finding{
					File:      path,
					Line:      ln,
					RuleName:  r.Name,
					Match:     m,
					Severity:  r.Severity,
					Category:  r.Category,
					Timestamp: time.Now(),
				})
			}
		}
	}
	if err := sc.Err(); err != nil && debug {
		log.Printf("Scanner error %s: %v", path, err)
	}
	return out, nil
}

// scanDir walks a directory to find files to scan, or gets them from git diff.
func scanDir(ctx context.Context, root string, useGit, debug bool, ignorePatterns []string) ([]Finding, error) {
	if debug {
		log.Printf("Starting scan in %s git=%v", root, useGit)
	}
	var files []string
	if useGit {
		fs, err := getGitChangedFiles(ctx)
		if err != nil {
			return nil, err
		}
		files = fs
	} else {
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && supportedExtensions[filepath.Ext(p)] && !shouldIgnore(p, ignorePatterns) {
				files = append(files, p)
			}
			return nil
		})
	}

	var all []Finding
	for _, f := range files {
		fs, err := scanFile(f, debug)
		if err != nil {
			log.Printf("Warning: scan %s: %v", f, err)
			continue
		}
		all = append(all, fs...)
	}
	return all, nil
}

// --- Output and Reporting ---

// summarize prints a human-readable summary of findings to standard output.
func summarize(findings []Finding) {
	sev, cat := map[string]int{}, map[string]int{}
	for _, f := range findings {
		sev[f.Severity]++
		cat[f.Category]++
	}
	// Using "---" instead of "[]" to avoid confusing the JSON parser in the orchestrator.
	fmt.Println("\n--- Severity Summary ---")
	for k, v := range sev {
		fmt.Printf("  %s: %d\n", k, v)
	}
	fmt.Println("\n--- OWASP Category Summary ---")
	for k, v := range cat {
		fmt.Printf("  %s: %d\n", k, v)
	}
}

// outputMarkdownBody generates a GitHub-flavored Markdown report.
func outputMarkdownBody(findings []Finding, verbose bool) string {
	var b strings.Builder
	b.WriteString("### 🔍 Static Analysis Findings\n\n")
	b.WriteString("| File | Line | Rule | Match | Severity | OWASP |\n")
	b.WriteString("|------|------|------|-------|----------|-------|\n")
	for _, f := range findings {
		b.WriteString(fmt.Sprintf("| `%s` | %d | %s | `%s` | **%s** | %s |\n",
			f.File, f.Line, f.RuleName, f.Match, f.Severity, f.Category))
	}
	if verbose {
		b.WriteString("\n---\n### 🛠 Remediation Brief\n\n")
		for _, f := range findings {
			r := ruleMap[f.RuleName]
			b.WriteString(fmt.Sprintf("- **%s:%d** – %s\n    - %s\n\n",
				f.File, f.Line, r.Name, r.Remediation))
		}
	}
	sevCount, catCount := map[string]int{}, map[string]int{}
	for _, f := range findings {
		sevCount[f.Severity]++
		catCount[f.Category]++
	}
	b.WriteString("---\n\n**Severity Summary**\n\n")
	for _, lvl := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if c, ok := sevCount[lvl]; ok {
			b.WriteString(fmt.Sprintf("- **%s**: %d\n", lvl, c))
		}
	}
	b.WriteString("\n**OWASP Category Summary**\n\n")
	for c, cnt := range catCount {
		b.WriteString(fmt.Sprintf("- **%s**: %d\n", c, cnt))
	}
	return b.String()
}

// postGitHubComment posts a comment to a GitHub Pull Request.
func postGitHubComment(body string) error {
	repo := os.Getenv("GITHUB_REPOSITORY")
	pr := os.Getenv("GITHUB_PR_NUMBER")
	tok := os.Getenv("GITHUB_TOKEN")
	if repo == "" || pr == "" || tok == "" {
		return fmt.Errorf("GitHub environment variables not set")
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/issues/%s/comments", repo, pr)
	payload := map[string]string{"body": body}
	data, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 201 {
		return fmt.Errorf("GitHub comment failed with status %d", resp.StatusCode)
	}
	return nil
}

// --- Main Execution Flow ---

func main() {
	// 1. Parse command-line flags.
	dir := flag.String("dir", ".", "Directory to scan")
	output := flag.String("output", "text", "Output: text/json/markdown")
	debug := flag.Bool("debug", false, "Debug mode")
	useGit := flag.Bool("git-diff", false, "Scan changed files only")
	exitHigh := flag.Bool("exit-high", false, "Exit 1 if any HIGH findings")
	ignoreFlag := flag.String("ignore", "vendor,node_modules,dist,public,build", "Ignore patterns")
	postToGitHub := flag.Bool("github-pr", false, "Post results to GitHub PR")
	verbose := flag.Bool("verbose", false, "Show short remediation advice")
	ruleFiles := flag.String("rules", "", "Comma-separated paths to external rules.json files (overrides built-in)")
	minSeverity := flag.String("severity", "", "Minimum severity to show (CRITICAL, HIGH, MEDIUM, LOW)")
	flag.Parse()

	if *minSeverity != "" {
		if _, ok := severityLevels[*minSeverity]; !ok {
			log.Fatalf("Invalid severity: %s. Valid: CRITICAL, HIGH, MEDIUM, LOW", *minSeverity)
		}
	}

	// 2. Load rules from specified files, or fall back to defaults.
	if *ruleFiles != "" {
		rules = nil
		ruleMap = make(map[string]Rule)
		parts := strings.Split(*ruleFiles, ",")
		for _, rf := range parts {
			rf = strings.TrimSpace(rf)
			if *debug {
				log.Printf("Loading rules from %s", rf)
			}
			loaded, err := loadRulesFromFile(rf)
			if err != nil {
				log.Fatalf("failed to load rules from %s: %v", rf, err)
			}
			for _, r := range loaded {
				rules = append(rules, r)
				ruleMap[r.Name] = r
			}
		}
	} else {
		if _, err := os.Stat("rules.json"); err == nil {
			if *debug {
				log.Println("No --rules flagged, loading rules.json")
			}
			loaded, err := loadRulesFromFile("rules.json")
			if err != nil {
				log.Fatalf("failed to load rules.json: %v", err)
			}
			rules = loaded
			ruleMap = make(map[string]Rule)
			for _, r := range rules {
				ruleMap[r.Name] = r
			}
		}
	}

	if *debug {
		log.Println("Debug mode enabled")
		if *minSeverity != "" {
			log.Printf("Filtering for severity >= %s", *minSeverity)
		}
	}

	// 3. Load ignore patterns.
	ignorePatterns, err := loadIgnorePatterns(*ignoreFlag)
	if err != nil {
		log.Fatalf("Failed loading ignore patterns: %v", err)
	}

	// 4. Execute the scan.
	allFindings, err := scanDir(context.Background(), *dir, *useGit, *debug, ignorePatterns)
	if err != nil {
		log.Fatalf("Scan error: %v", err)
	}
	findings := filterBySeverity(allFindings, *minSeverity)

	// 5. Sort findings for consistent output.
	sort.Slice(findings, func(i, j int) bool {
		si := severityLevels[findings[i].Severity]
		sj := severityLevels[findings[j].Severity]
		if si != sj {
			return si > sj
		}
		if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	// 6. Handle human-readable summaries for non-JSON output.
	if *output != "json" {
		if len(findings) == 0 {
			if *minSeverity != "" && len(allFindings) > 0 {
				fmt.Fprintf(os.Stderr, "✅ No issues at %s or above.\n", *minSeverity)
			} else {
				fmt.Fprintln(os.Stderr, "✅ No issues found.")
			}
			if *output != "json" {
				return
			}
		}

		if *minSeverity != "" {
			fmt.Fprintf(os.Stderr, "Showing findings >= %s. %d of %d total.\n", *minSeverity, len(findings), len(allFindings))
		}
		summarize(findings)
	}

	// 7. Print the final report based on the selected output format.
	switch *output {
	case "text":
		for _, f := range findings {
			fmt.Printf("[%s] %s:%d - %s (%s)\n",
				f.Severity, f.File, f.Line, f.Match, f.Category)
		}
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(findings)
	case "markdown":
		body := outputMarkdownBody(findings, *verbose)
		fmt.Println(body)
		if *postToGitHub {
			if err := postGitHubComment(body); err != nil {
				log.Printf("GitHub comment failed: %v", err)
			} else {
				fmt.Println("✅ Comment posted.")
			}
		}
	default:
		log.Fatalf("Unsupported output: %s", *output)
	}

	// 8. Exit with an error code if critical findings are found (for CI/CD).
	if *exitHigh {
		for _, f := range findings {
			if f.Severity == "HIGH" {
				os.Exit(1)
			}
		}
	}
}
