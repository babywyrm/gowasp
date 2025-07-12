//go:build ignore
// +build ignore

package main

import (
  "encoding/json"
  "fmt"
  "os"
)

// exportRule is the shape we want in JSON:
type exportRule struct {
  Name        string `json:"name"`
  Pattern     string `json:"pattern"`
  Severity    string `json:"severity"`
  Category    string `json:"category"`
  Description string `json:"description"`
  Remediation string `json:"remediation"`
}

func main() {
  // InitRules will compile and append extended+extra into the global 'rules' slice
  ruleMap := InitRules()

  // Gather them in a stable order (map iteration is random):
  var exports []exportRule
  for _, r := range ruleMap {
    exports = append(exports, exportRule{
      Name:        r.Name,
      Pattern:     r.Regex,
      Severity:    r.Severity,
      Category:    r.Category,
      Description: r.Description,
      Remediation: r.Remediation,
    })
  }

  // Optional: sort by Name so the JSON file is reproducible.
  // import "sort"
  // sort.Slice(exports, func(i, j int) bool {
  //   return exports[i].Name < exports[j].Name
  // })

  out, err := json.MarshalIndent(exports, "", "  ")
  if err != nil {
    fmt.Fprintf(os.Stderr, "marshal error: %v\n", err)
    os.Exit(1)
  }

  // Write to stdout (so you can redirect):
  fmt.Println(string(out))
}
