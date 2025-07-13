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

type Rule struct {
  Name        string
  Regex       string
  Pattern     *regexp.Regexp
  Severity    string
  Category    string
  Description string
  Remediation string
}

type Finding struct {
  File      string    `json:"file"`
  Line      int       `json:"line"`
  RuleName  string    `json:"rule_name"`
  Match     string    `json:"match"`
  Severity  string    `json:"severity"`
  Category  string    `json:"category"`
  Timestamp time.Time `json:"timestamp"`
}

var rules []Rule
var ruleMap = map[string]Rule{}

var supportedExtensions = map[string]bool{
  ".go": true, ".js": true, ".py": true, ".java": true, ".html": true, ".php": true,
}

var severityLevels = map[string]int{
  "CRITICAL": 4,
  "HIGH":     3,
  "MEDIUM":   2,
  "LOW":      1,
}

// Config holds CLI flag values.
type Config struct {
  Dir         string
  RuleFiles   []string
  MinSeverity string
  IgnoreGlobs []string
  UseGitDiff  bool
  Output      string
  Debug       bool
  ExitHigh    bool
  PostToPR    bool
  Verbose     bool
}

// check fatals on error.
func check(err error, msg string) {
  if err != nil {
    log.Fatalf("%s: %v", msg, err)
  }
}

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

func loadRulesFromFile(path string) ([]Rule, error) {
  data, err := ioutil.ReadFile(path)
  if err != nil {
    return nil, err
  }
  var jr []struct {
    Name, Pattern, Severity, Category, Description, Remediation string
  }
  if err := json.Unmarshal(data, &jr); err != nil {
    return nil, fmt.Errorf("invalid JSON in %s: %w", path, err)
  }
  out := make([]Rule, len(jr))
  for i, r := range jr {
    re, err := regexp.Compile(r.Pattern)
    if err != nil {
      return nil, fmt.Errorf("regex compile error for %q in %s[%d]: %v",
        r.Name, path, i, err)
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

func meetsThreshold(fsev, minsev string) bool {
  if minsev == "" {
    return true
  }
  fl, ok1 := severityLevels[fsev]
  ml, ok2 := severityLevels[minsev]
  if !ok1 || !ok2 {
    return true
  }
  return fl >= ml
}

func filterBySeverity(findings []Finding, minsev string) []Finding {
  if minsev == "" {
    return findings
  }
  var out []Finding
  for _, f := range findings {
    if meetsThreshold(f.Severity, minsev) {
      out = append(out, f)
    }
  }
  return out
}

func runCommand(ctx context.Context, cmd string, args ...string) (string, error) {
  c := exec.CommandContext(ctx, cmd, args...)
  out, err := c.CombinedOutput()
  return string(out), err
}

func loadIgnorePatterns(ignoreFlag string) []string {
  pats := []string{}
  if ignoreFlag != "" {
    pats = append(pats, strings.Split(ignoreFlag, ",")...)
  }
  f, err := os.Open(".scannerignore")
  if err == nil {
    defer f.Close()
    sc := bufio.NewScanner(f)
    for sc.Scan() {
      l := strings.TrimSpace(sc.Text())
      if l != "" && !strings.HasPrefix(l, "#") {
        pats = append(pats, l)
      }
    }
  }
  return pats
}

func shouldIgnore(path string, patterns []string) bool {
  for _, pat := range patterns {
    if ok, _ := doublestar.PathMatch(pat, path); ok {
      return true
    }
  }
  return false
}

func scanFile(path string, debug bool) []Finding {
  if debug {
    log.Printf("Scanning %s", path)
  }
  var findings []Finding
  f, err := os.Open(path)
  if err != nil {
    log.Printf("open %s: %v", path, err)
    return findings
  }
  defer f.Close()

  sc := bufio.NewScanner(f)
  sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
  ln := 0
  for sc.Scan() {
    ln++
    txt := sc.Text()
    if len(txt) > 100000 {
      if debug {
        log.Printf("skip long line %d in %s", ln, path)
      }
      continue
    }
    for _, r := range rules {
      if r.Pattern.MatchString(txt) {
        m := r.Pattern.FindString(txt)
        if len(m) > 80 {
          m = m[:80] + "..."
        }
        findings = append(findings, Finding{
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
  return findings
}

func scanDir(ctx context.Context, cfg Config) ([]Finding, error) {
  if cfg.Debug {
    log.Printf("Starting scan dir=%s gitDiff=%v", cfg.Dir, cfg.UseGitDiff)
  }
  var files []string
  if cfg.UseGitDiff {
    out, err := runCommand(ctx, "git", "diff", "--name-only", "HEAD~1")
    if err != nil {
      return nil, err
    }
    files = strings.Split(strings.TrimSpace(out), "\n")
  } else {
    ignorePatterns := loadIgnorePatterns(strings.Join(cfg.IgnoreGlobs, ","))
    filepath.WalkDir(cfg.Dir, func(p string, d os.DirEntry, err error) error {
      if err != nil {
        return err
      }
      if !d.IsDir() && supportedExtensions[filepath.Ext(p)] &&
        !shouldIgnore(p, ignorePatterns) {
        files = append(files, p)
      }
      return nil
    })
  }

  var all []Finding
  for _, p := range files {
    all = append(all, scanFile(p, cfg.Debug)...)
  }
  return all, nil
}

func summarize(findings []Finding) {
  sev, cat := map[string]int{}, map[string]int{}
  for _, f := range findings {
    sev[f.Severity]++
    cat[f.Category]++
  }
  fmt.Println("\n[ Severity Summary ]")
  for k, v := range sev {
    fmt.Printf("  %s: %d\n", k, v)
  }
  fmt.Println("\n[ OWASP Category Summary ]")
  for k, v := range cat {
    fmt.Printf("  %s: %d\n", k, v)
  }
}

func spinner(stop chan struct{}) {
  frames := []rune{'⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'}
  i := 0
  for {
    select {
    case <-stop:
      fmt.Fprint(os.Stderr, "\r")
      return
    default:
      fmt.Fprintf(os.Stderr, "\r%s Scanning...", string(frames[i%len(frames)]))
      time.Sleep(100 * time.Millisecond)
      i++
    }
  }
}

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
  b.WriteString("---\n\n**Severity Summary**\n\n")
  sevCount := map[string]int{}
  catCount := map[string]int{}
  for _, f := range findings {
    sevCount[f.Severity]++
    catCount[f.Category]++
  }
  for _, lvl := range []string{"CRITICAL","HIGH","MEDIUM","LOW"} {
    if c, ok := sevCount[lvl]; ok {
      b.WriteString(fmt.Sprintf("- **%s**: %d\n", lvl, c))
    }
  }
  b.WriteString("\n**OWASP Category Summary**\n\n")
  for k, v := range catCount {
    b.WriteString(fmt.Sprintf("- **%s**: %d\n", k, v))
  }
  return b.String()
}

func postGitHubComment(body string) error {
  repo := os.Getenv("GITHUB_REPOSITORY")
  pr := os.Getenv("GITHUB_PR_NUMBER")
  tok := os.Getenv("GITHUB_TOKEN")
  if repo == "" || pr == "" || tok == "" {
    return fmt.Errorf("GitHub environment variables not set")
  }
  url := fmt.Sprintf("https://api.github.com/repos/%s/issues/%s/comments", repo, pr)
  data, _ := json.Marshal(map[string]string{"body": body})
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
    return fmt.Errorf("GitHub comment failed: %d", resp.StatusCode)
  }
  return nil
}

func main() {
  var cfg Config
  var rulesFlag, ignoreFlag string

  flag.StringVar(&cfg.Dir, "dir", ".", "Directory to scan")
  flag.StringVar(&rulesFlag, "rules", "", "Comma-separated rule JSON files")
  flag.StringVar(&cfg.MinSeverity, "severity", "", "Min severity: CRITICAL,HIGH,MEDIUM,LOW")
  flag.StringVar(&ignoreFlag, "ignore", "vendor,node_modules,dist,public,build", "Ignore patterns")
  flag.StringVar(&cfg.Output, "output", "text", "text/json/markdown")
  flag.BoolVar(&cfg.Debug, "debug", false, "Debug mode")
  flag.BoolVar(&cfg.UseGitDiff, "git-diff", false, "Scan only git diff")
  flag.BoolVar(&cfg.ExitHigh, "exit-high", false, "Exit on HIGH findings")
  flag.BoolVar(&cfg.PostToPR, "github-pr", false, "Post to GitHub PR")
  flag.BoolVar(&cfg.Verbose, "verbose", false, "Show remediation")
  flag.Parse()

  if rulesFlag != "" {
    cfg.RuleFiles = strings.Split(rulesFlag, ",")
  } else if _, err := os.Stat("rules.json"); err == nil {
    cfg.RuleFiles = []string{"rules.json"}
    if cfg.Debug {
      log.Println("Using default rules.json")
    }
  }
  cfg.IgnoreGlobs = strings.Split(ignoreFlag, ",")

  if cfg.MinSeverity != "" {
    if _, ok := severityLevels[cfg.MinSeverity]; !ok {
      log.Fatalf("Invalid severity: %s", cfg.MinSeverity)
    }
  }

  rules = InitRules()
  for _, rf := range cfg.RuleFiles {
    rl, err := loadRulesFromFile(rf)
    check(err, "loading "+rf)
    rules = append(rules, rl...)
  }
  ruleMap = make(map[string]Rule)
  for _, r := range rules {
    ruleMap[r.Name] = r
  }

  stop := make(chan struct{})
  go spinner(stop)

  allFindings, err := scanDir(context.Background(), cfg)
  close(stop)
  fmt.Fprintln(os.Stderr)
  check(err, "scanDir")

  findings := filterBySeverity(allFindings, cfg.MinSeverity)
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

  if len(findings) == 0 {
    fmt.Println("✅ No issues found.")
    return
  }
  fmt.Printf("Showing findings ≥%s (total %d)\n\n", cfg.MinSeverity, len(findings))
  summarize(findings)

  switch cfg.Output {
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
    body := outputMarkdownBody(findings, cfg.Verbose)
    fmt.Println(body)
    if cfg.PostToPR {
      check(postGitHubComment(body), "postGitHubComment")
      fmt.Println("✅ Comment posted.")
    }
  default:
    log.Fatalf("Unsupported output: %s", cfg.Output)
  }

  if cfg.ExitHigh {
    for _, f := range findings {
      if f.Severity == "HIGH" {
        os.Exit(1)
      }
    }
  }
}
