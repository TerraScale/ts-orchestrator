package main

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
)

func loadDeclarations(dir string) (map[string][]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	declared := map[string][]string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var spec struct {
			Name    string   `json:"name"`
			Regions []string `json:"regions"`
		}
		if err := protocol.DecodeTolerant(data, &spec, 64<<10); err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		if spec.Name == "" {
			return nil, fmt.Errorf("%s: declaration has no name", entry.Name())
		}
		if _, exists := declared[spec.Name]; exists {
			return nil, fmt.Errorf("%s: duplicate declaration %s", entry.Name(), spec.Name)
		}
		declared[spec.Name] = spec.Regions
	}
	return declared, nil
}

func declarationFinding(declared map[string][]string, name, region string, app releasepush.AppDeployment) (finding, bool) {
	regions, known := declared[name]
	if !known {
		return finding{}, false
	}
	if len(regions) > 0 && !slices.Contains(regions, region) {
		return finding{line: fmt.Sprintf("%s %s: state=ok not-declared", name, region)}, true
	}
	reason := notDeclaredReason(app)
	if reason == "" {
		return finding{}, false
	}
	return finding{line: fmt.Sprintf("%s %s: state=red declaration lists %s but %s reports %q", name, region, region, cmp.Or(app.Host, region), reason), red: true}, true
}

func notDeclaredReason(app releasepush.AppDeployment) string {
	if strings.Contains(app.Reason, "not declared") {
		return app.Reason
	}
	for _, task := range app.Tasks {
		if strings.Contains(task.Reason, "not declared") {
			return task.Reason
		}
	}
	return ""
}
