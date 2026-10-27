// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

type golangciBaselineConfig struct {
	Version string `yaml:"version"`
	Linters struct {
		Exclusions struct {
			Rules []golangciBaselineRule `yaml:"rules"`
		} `yaml:"exclusions"`
	} `yaml:"linters"`
}

type golangciBaselineRule struct {
	HeadComment string
	Path        string   `yaml:"path"`
	Linters     []string `yaml:"linters"`
	Text        string   `yaml:"text"`
	Source      string   `yaml:"source"`
}

func (r *golangciBaselineRule) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("expected mapping node for exclusion rule, got kind %d", value.Kind)
	}
	comment := value.HeadComment
	if comment == "" && len(value.Content) > 0 {
		comment = value.Content[0].HeadComment
	}
	type rawRule struct {
		Path    string   `yaml:"path"`
		Linters []string `yaml:"linters"`
		Text    string   `yaml:"text"`
		Source  string   `yaml:"source"`
	}
	var decoded rawRule
	if err := value.Decode(&decoded); err != nil {
		return err
	}
	r.HeadComment = comment
	r.Path = decoded.Path
	r.Linters = decoded.Linters
	r.Text = decoded.Text
	r.Source = decoded.Source
	return nil
}

func parseBaselineLocationsComment(comment string) ([]int, error) {
	const prefix = "# Baseline locations: "
	var matched string
	for _, rawLine := range strings.Split(comment, "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, prefix) {
			if matched != "" {
				return nil, fmt.Errorf("duplicate baseline locations comment %q", line)
			}
			matched = strings.TrimPrefix(line, prefix)
		}
	}
	if matched == "" {
		return nil, fmt.Errorf("missing %q comment", strings.TrimSpace(prefix))
	}
	parts := strings.Split(matched, ", ")
	lines := make([]int, 0, len(parts))
	for _, part := range parts {
		fields := strings.Split(part, ":")
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid baseline location %q", part)
		}
		lineNum, err := strconv.Atoi(fields[0])
		if err != nil || lineNum < 1 || strconv.Itoa(lineNum) != fields[0] {
			return nil, fmt.Errorf("invalid baseline line number in %q", part)
		}
		colNum, err := strconv.Atoi(fields[1])
		if err != nil || colNum < 1 || strconv.Itoa(colNum) != fields[1] {
			return nil, fmt.Errorf("invalid baseline column number in %q", part)
		}
		lines = append(lines, lineNum)
	}
	return lines, nil
}

func validateGolangciBaseline(configBytes []byte, repoRoot string) error {
	var cfg golangciBaselineConfig
	if err := yaml.Unmarshal(configBytes, &cfg); err != nil {
		return fmt.Errorf("unmarshal .golangci.yml: %w", err)
	}
	if cfg.Version != "2" {
		return fmt.Errorf("expected version \"2\", got %q", cfg.Version)
	}
	rules := cfg.Linters.Exclusions.Rules
	if len(rules) == 0 {
		return fmt.Errorf("expected non-empty linters.exclusions.rules")
	}
	fileCache := make(map[string][]string)
	for i, rule := range rules {
		if !strings.HasPrefix(rule.Path, "^") || !strings.HasSuffix(rule.Path, "$") || len(rule.Path) <= 2 {
			return fmt.Errorf("rule %d: path %q is not anchored with ^...$", i, rule.Path)
		}
		pathRe, err := regexp.Compile(rule.Path)
		if err != nil {
			return fmt.Errorf("rule %d: invalid path regex %q: %w", i, rule.Path, err)
		}
		if len(rule.Linters) == 0 {
			return fmt.Errorf("rule %d (%s): linters must be non-empty", i, rule.Path)
		}
		for _, linter := range rule.Linters {
			if strings.TrimSpace(linter) == "" {
				return fmt.Errorf("rule %d (%s): empty linter entry", i, rule.Path)
			}
		}
		if !strings.HasPrefix(rule.Text, "^") || !strings.HasSuffix(rule.Text, "$") || len(rule.Text) <= 2 {
			return fmt.Errorf("rule %d (%s): text %q is not anchored with ^...$", i, rule.Path, rule.Text)
		}
		if _, err := regexp.Compile(rule.Text); err != nil {
			return fmt.Errorf("rule %d (%s): invalid text regex %q: %w", i, rule.Path, rule.Text, err)
		}
		if rule.Text == "^Error return value is not checked$" && strings.TrimSpace(rule.Source) == "" {
			return fmt.Errorf("rule %d (%s): generic text %q requires a source anchor", i, rule.Path, rule.Text)
		}
		if strings.TrimSpace(rule.Source) == "" {
			return fmt.Errorf("rule %d (%s): missing source anchor", i, rule.Path)
		}
		if !strings.HasPrefix(rule.Source, `^\s*`) || !strings.HasSuffix(rule.Source, `\s*$`) {
			return fmt.Errorf("rule %d (%s): source %q is not anchored as ^\\s*...\\s*$", i, rule.Path, rule.Source)
		}
		innerSource := strings.TrimSuffix(strings.TrimPrefix(rule.Source, `^\s*`), `\s*$`)
		if strings.TrimSpace(innerSource) == "" {
			return fmt.Errorf("rule %d (%s): source %q has empty body", i, rule.Path, rule.Source)
		}
		sourceRe, err := regexp.Compile(rule.Source)
		if err != nil {
			return fmt.Errorf("rule %d (%s): invalid source regex %q: %w", i, rule.Path, rule.Source, err)
		}
		if sourceRe.MatchString("__golangci_baseline_unmatched_probe__") {
			return fmt.Errorf("rule %d (%s): source %q matches arbitrary probe text", i, rule.Path, rule.Source)
		}
		lineNumbers, err := parseBaselineLocationsComment(rule.HeadComment)
		if err != nil {
			return fmt.Errorf("rule %d (%s): %w", i, rule.Path, err)
		}
		relPath := strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(rule.Path, "^"), "$"), `\.`, ".")
		if filepath.Clean(relPath) != relPath || filepath.IsAbs(relPath) || strings.HasPrefix(relPath, "../") || !pathRe.MatchString(relPath) {
			return fmt.Errorf("rule %d: path regex %q does not resolve to a clean relative path (%q)", i, rule.Path, relPath)
		}
		lines, cached := fileCache[relPath]
		if !cached {
			content, readErr := os.ReadFile(filepath.Join(repoRoot, relPath))
			if readErr != nil {
				return fmt.Errorf("rule %d: read %s: %w", i, relPath, readErr)
			}
			lines = strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
			fileCache[relPath] = lines
		}
		for _, lineNum := range lineNumbers {
			if lineNum > len(lines) {
				return fmt.Errorf("rule %d (%s): baseline location line %d exceeds file length %d", i, relPath, lineNum, len(lines))
			}
			actualLine := lines[lineNum-1]
			if strings.TrimSpace(actualLine) == "" {
				return fmt.Errorf("rule %d (%s): baseline location line %d is blank", i, relPath, lineNum)
			}
			if !sourceRe.MatchString(actualLine) || !sourceRe.MatchString(strings.TrimSpace(actualLine)) {
				return fmt.Errorf("rule %d (%s:%d): source %q does not match actual line %q", i, relPath, lineNum, rule.Source, actualLine)
			}
		}
	}
	return nil
}

func TestGolangciBaselineExclusionsAreSourceAnchoredAndMatchLocations(t *testing.T) {
	fixtureDir := t.TempDir()
	fixtureRel := "pkg/sample/sample.go"
	fixtureFile := filepath.Join(fixtureDir, fixtureRel)
	if err := os.MkdirAll(filepath.Dir(fixtureFile), 0700); err != nil {
		t.Fatal(err)
	}
	fixtureContent := "package sample\n\nfunc run() {\n\tdefer response.Body.Close()\n\tcase <-done:\n}\n"
	if err := os.WriteFile(fixtureFile, []byte(fixtureContent), 0600); err != nil {
		t.Fatal(err)
	}

	validFixtureYAML := `version: "2"
linters:
  exclusions:
    rules:
      # Baseline locations: 4:2
      - path: '^pkg/sample/sample\.go$'
        linters: [errcheck]
        text: '^Error return value of ` + "`response\\.Body\\.Close`" + ` is not checked$'
        source: '^\s*defer response\.Body\.Close\(\)\s*$'
`

	// Unhappy paths first: verify each invalid configuration is rejected.
	negativeCases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing-source",
			yaml: `version: "2"
linters:
  exclusions:
    rules:
      # Baseline locations: 4:2
      - path: '^pkg/sample/sample\.go$'
        linters: [errcheck]
        text: '^Error return value of ` + "`response\\.Body\\.Close`" + ` is not checked$'
`,
			want: "missing source anchor",
		},
		{
			name: "generic-text-without-source",
			yaml: `version: "2"
linters:
  exclusions:
    rules:
      # Baseline locations: 5:2
      - path: '^pkg/sample/sample\.go$'
        linters: [errcheck]
        text: '^Error return value is not checked$'
`,
			want: "generic text \"^Error return value is not checked$\" requires a source anchor",
		},
		{
			name: "unanchored-source-prefix",
			yaml: `version: "2"
linters:
  exclusions:
    rules:
      # Baseline locations: 4:2
      - path: '^pkg/sample/sample\.go$'
        linters: [errcheck]
        text: '^Error return value of ` + "`response\\.Body\\.Close`" + ` is not checked$'
        source: 'defer response\.Body\.Close\(\)\s*$'
`,
			want: `is not anchored as ^\s*...\s*$`,
		},
		{
			name: "unanchored-source-suffix",
			yaml: `version: "2"
linters:
  exclusions:
    rules:
      # Baseline locations: 4:2
      - path: '^pkg/sample/sample\.go$'
        linters: [errcheck]
        text: '^Error return value of ` + "`response\\.Body\\.Close`" + ` is not checked$'
        source: '^\s*defer response\.Body\.Close\(\)'
`,
			want: `is not anchored as ^\s*...\s*$`,
		},
		{
			name: "source-matches-no-recorded-line",
			yaml: `version: "2"
linters:
  exclusions:
    rules:
      # Baseline locations: 4:2
      - path: '^pkg/sample/sample\.go$'
        linters: [errcheck]
        text: '^Error return value of ` + "`response\\.Body\\.Close`" + ` is not checked$'
        source: '^\s*defer other\.Close\(\)\s*$'
`,
			want: "does not match actual line",
		},
		{
			name: "source-partially-mismatches-multi-location-rule",
			yaml: `version: "2"
linters:
  exclusions:
    rules:
      # Baseline locations: 4:2, 5:2
      - path: '^pkg/sample/sample\.go$'
        linters: [errcheck]
        text: '^Error return value is not checked$'
        source: '^\s*defer response\.Body\.Close\(\)\s*$'
`,
			want: "pkg/sample/sample.go:5",
		},
		{
			name: "wrong-version",
			yaml: strings.Replace(validFixtureYAML, `version: "2"`, `version: "1"`, 1),
			want: `expected version "2"`,
		},
		{
			name: "unanchored-path",
			yaml: strings.Replace(validFixtureYAML, `'^pkg/sample/sample\.go$'`, `'pkg/sample/sample\.go$'`, 1),
			want: "is not anchored with ^...$",
		},
		{
			name: "empty-linters",
			yaml: strings.Replace(validFixtureYAML, `linters: [errcheck]`, `linters: []`, 1),
			want: "linters must be non-empty",
		},
		{
			name: "unanchored-text",
			yaml: strings.Replace(validFixtureYAML, `text: '^Error`, `text: 'Error`, 1),
			want: "is not anchored with ^...$",
		},
		{
			name: "invalid-source-regex",
			yaml: strings.Replace(validFixtureYAML, `defer response\.Body\.Close\(\)`, `defer response\.Body\.Close(`, 1),
			want: "invalid source regex",
		},
		{
			name: "wildcard-source-regex",
			yaml: strings.Replace(validFixtureYAML, `defer response\.Body\.Close\(\)`, `.*`, 1),
			want: "matches arbitrary probe text",
		},
		{
			name: "missing-baseline-locations-comment",
			yaml: strings.Replace(validFixtureYAML, "      # Baseline locations: 4:2\n", "", 1),
			want: `missing "# Baseline locations:" comment`,
		},
		{
			name: "out-of-range-baseline-line",
			yaml: strings.Replace(validFixtureYAML, "# Baseline locations: 4:2", "# Baseline locations: 99:2", 1),
			want: "exceeds file length",
		},
		{
			name: "blank-baseline-line",
			yaml: strings.Replace(validFixtureYAML, "# Baseline locations: 4:2", "# Baseline locations: 2:1", 1),
			want: "is blank",
		},
	}

	for _, tc := range negativeCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGolangciBaseline([]byte(tc.yaml), fixtureDir)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}

	if err := validateGolangciBaseline([]byte(validFixtureYAML), fixtureDir); err != nil {
		t.Fatalf("valid in-memory control failed: %v", err)
	}

	repoRoot := "../.."
	configPath := filepath.Join(repoRoot, ".golangci.yml")
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read %s: %v", configPath, err)
	}
	if err := validateGolangciBaseline(configBytes, repoRoot); err != nil {
		t.Fatalf("repository .golangci.yml failed baseline validation: %v", err)
	}

	var cfg golangciBaselineConfig
	if err := yaml.Unmarshal(configBytes, &cfg); err != nil {
		t.Fatalf("unmarshal repository .golangci.yml: %v", err)
	}
	if len(cfg.Linters.Exclusions.Rules) != 322 {
		t.Fatalf("expected 322 baseline exclusion rules, got %d", len(cfg.Linters.Exclusions.Rules))
	}
}
