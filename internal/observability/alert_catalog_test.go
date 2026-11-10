package observability

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestAlertExprsUseExportedMetrics(t *testing.T) {
	root := filepath.Join("..", "..", "deploy", "observability")
	catalog := map[string]struct{}{}
	raw, err := os.ReadFile(filepath.Join(root, "production", "metric-catalog.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			catalog[line] = struct{}{}
		}
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".yml") && !strings.HasSuffix(path, ".test.yml") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, expr := range ruleExprs(string(body)) {
			for _, name := range metricsInExpr(expr) {
				if _, ok := catalog[name]; !ok {
					t.Errorf("%s references %q which is absent from metric-catalog.txt", path, name)
				}
			}
		}
	}
}

func ruleExprs(body string) []string {
	var out []string
	lines := strings.Split(body, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "expr:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "expr:"))
		if rest != "|" && rest != ">" {
			out = append(out, rest)
			continue
		}
		base := len(line) - len(strings.TrimLeft(line, " "))
		var block []string
		for i+1 < len(lines) {
			next := lines[i+1]
			if strings.TrimSpace(next) == "" {
				block = append(block, "")
				i++
				continue
			}
			indent := len(next) - len(strings.TrimLeft(next, " "))
			if indent <= base {
				break
			}
			block = append(block, strings.TrimSpace(next))
			i++
		}
		out = append(out, strings.Join(block, " "))
	}
	return out
}

var (
	quoted    = regexp.MustCompile(`"(?:\\.|[^"])*"|'(?:\\.|[^'])*'`)
	braces    = regexp.MustCompile(`\{[^{}]*\}`)
	ranges    = regexp.MustCompile(`\[[^\]]*\]`)
	aggClause = regexp.MustCompile(`(?i)\b(?:by|on|without|ignoring)\s*\([^)]*\)`)
	ident     = regexp.MustCompile(`(?:^|[^A-Za-z0-9_:])([A-Za-z_:][A-Za-z0-9_:]*)`)
	promFuncs = map[string]struct{}{}
)

func init() {
	for name := range strings.SplitSeq("rate irate increase delta deriv sum min max avg count stddev stdvar topk bottomk quantile histogram_quantile clamp clamp_min clamp_max abs ceil floor round ln log2 log10 sqrt exp sgn label_replace label_join absent absent_over_time present_over_time count_over_time changes resets predict_linear holt_winters vector scalar time timestamp day_of_month day_of_week day_of_year days_in_month hour minute month year group and or unless by on ignoring without group_left group_right bool offset inf nan", " ") {
		promFuncs[name] = struct{}{}
	}
}

func metricsInExpr(expr string) []string {
	expr = quoted.ReplaceAllString(expr, " ")
	expr = braces.ReplaceAllString(expr, " ")
	expr = ranges.ReplaceAllString(expr, " ")
	expr = aggClause.ReplaceAllString(expr, " ")
	var names []string
	for _, match := range ident.FindAllStringSubmatch(expr, -1) {
		name := match[1]
		if _, skip := promFuncs[name]; skip {
			continue
		}
		names = append(names, name)
	}
	return names
}
