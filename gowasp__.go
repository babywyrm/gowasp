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
  ".go": true, ".js": true, ".py": true,
  ".java": true, ".html": true, ".php": true,
}

// Severity levels (highest first)
var severityLevels = map[string]int{
  "CRITICAL": 4,
  "HIGH":     3,
  "MEDIUM":   2,
  "LOW":      1,
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
        "failed to compile regex for rule %q in %s[%d]: %v",
        r.Name, path, i, err,
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

func meetsThreshold(findingSeverity, minSeverity string) bool {
  if minSeverity == "" {
    return true
  }
  fl, ok1 := severityLevels[findingSeverity]
  ml, ok2 := severityLevels[minSeverity]
  if !ok1 || !ok2 {
    return true
  }
  return fl >= ml
}

func filterBySeverity(findings []Finding, minSeverity string) []Finding {
  if minSeverity == "" {
    return findings
  }
  var out []Finding
  for _, f := range findings {
    if meetsThreshold(f.Severity, minSeverity) {
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

func loadIgnorePatterns(ignoreFlag string) ([]string, error) {
  pats := []string{}
  if ignoreFlag != "" {
    pats = append(pats, strings.Split(ignoreFlag, ",")...)
  }
  f, err := os.Open(".scannerignore")
  if err != nil && !os.IsNotExist(err) {
    return nil, err
  }
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
  return pats, nil
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
    log.Printf("Scanning file: %s", path)
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

func scanDir(ctx context.Context, root string, useGit, debug bool, ignorePatterns []string) ([]Finding, error) {
  if debug {
    log.Printf("Starting scan in %s (git=%v)", root, useGit)
  }
  var files []string
  if useGit {
    out, err := runCommand(ctx, "git", "diff", "--name-only", "HEAD~1")
    if err != nil {
      return nil, err
    }
    files = strings.Split(strings.TrimSpace(out), "\n")
  } else {
    filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
      if err != nil {
        return err
      }
      if !d.IsDir() && supportedExtensions[filepath.Ext(path)] && !shouldIgnore(path, ignorePatterns) {
        files = append(files, path)
      }
      return nil
    })
  }

  var all []Finding
  for _, p := range files {
    fs := scanFile(p, debug)
    all = append(all, fs...)
  }
  return all, nil
}

func summarize(findings []Finding) {
  sev := map[string]int{}
  cat := map[string]int{}
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
      fmt.Fprint(os.Stderr, "\r") // clear
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
  for _, lvl := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
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
  dir := flag.String("dir", ".", "Directory to scan")
  rulesFlag := flag.String("rules", "", "Comma-separated rule JSON files")
  minSeverity := flag.String("severity", "", "Min severity: CRITICAL,HIGH,MEDIUM,LOW")
  ignoreFlag := flag.String("ignore", "vendor,node_modules,dist,public,build", "Ignore patterns")
  output := flag.String("output", "text", "text/json/markdown")
  debug := flag.Bool("debug", false, "Debug mode")
  useGit := flag.Bool("git-diff", false, "Scan changed files only")
  exitHigh := flag.Bool("exit-high", false, "Exit on HIGH")
  postPR := flag.Bool("github-pr", false, "Post to GitHub PR")
  verbose := flag.Bool("verbose", false, "Show remediation")
  flag.Parse()

  // Load rules
  rules = InitRules()
  if *rulesFlag != "" {
    for _, rf := range strings.Split(*rulesFlag, ",") {
      loaded, err := loadRulesFromFile(rf)
      if err != nil {
        log.Fatalf("loading %s: %v", rf, err)
      }
      rules = append(rules, loaded...)
    }
  } else if _, err := os.Stat("rules.json"); err == nil {
    loaded, err := loadRulesFromFile("rules.json")
    if err != nil {
      log.Fatalf("loading rules.json: %v", err)
    }
    rules = append(rules, loaded...)
  }
  ruleMap = make(map[string]Rule)
  for _, r := range rules {
    ruleMap[r.Name] = r
  }

  // Prepare ignore patterns
  ignores, err := loadIgnorePatterns(*ignoreFlag)
  if err != nil {
    log.Fatalf("loading ignore patterns: %v", err)
  }

  // Start spinner
  stop := make(chan struct{})
  go spinner(stop)

  // Scan
  allFindings, err := scanDir(context.Background(), *dir, *useGit, *debug, ignores)
  close(stop)
  fmt.Fprintln(os.Stderr)
  if err != nil {
    log.Fatalf("scan error: %v", err)
  }

  // Filter and sort
  findings := filterBySeverity(allFindings, *minSeverity)
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

  fmt.Printf("Showing findings >= %s (total %d)\n\n", *minSeverity, len(findings))
  summarize(findings)

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
    if *postPR {
      if err := postGitHubComment(body); err != nil {
        log.Printf("GitHub comment failed: %v", err)
      } else {
        fmt.Println("✅ Comment posted.")
      }
    }
  default:
    log.Fatalf("Unsupported output: %s", *output)
  }

  if *exitHigh {
    for _, f := range findings {
      if f.Severity == "HIGH" {
        os.Exit(1)
      }
    }
  }
}
