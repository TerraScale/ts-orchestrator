package main

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
)

func declaredServices(regions []releasepush.Region) (map[string]map[string]bool, error) {
	declared := map[string]map[string]bool{}
	for _, region := range regions {
		declared[region.Region] = map[string]bool{"ts-orchestrator": true}
		directory := filepath.Join("deploy/m1/services", region.Region)
		regional := true
		if _, err := os.Stat(directory); errors.Is(err, os.ErrNotExist) {
			directory, regional = "deploy/m1/services", false
		} else if err != nil {
			return nil, err
		}
		for _, x := range artifacts {
			if x.name == "ts-orchestrator" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(directory, x.name+".json"))
			if regional && errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			var spec struct {
				Name    string   `json:"name"`
				Regions []string `json:"regions"`
			}
			if err := json.Unmarshal(data, &spec); err != nil {
				return nil, err
			}
			if spec.Name != x.name || regional && !slices.Contains(spec.Regions, region.Region) {
				return nil, fmt.Errorf("%s: declaration identity or region mismatch", x.name)
			}
			declared[region.Region][x.name] = len(spec.Regions) == 0 || slices.Contains(spec.Regions, region.Region)
		}
	}
	return declared, nil
}
