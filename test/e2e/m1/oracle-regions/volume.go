package main

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/oraclehost"
)

func reattachSwarm(from, to *oraclehost.Host, relabel func(map[string]any)) {
	source, target := from.State("swarm"), to.State("swarm")
	must(filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		copied := filepath.Join(target, strings.TrimPrefix(path, source))
		switch {
		case entry.IsDir():
			return os.MkdirAll(copied, 0o700)
		case entry.Type().IsRegular():
			info, err := entry.Info()
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(copied, data, info.Mode().Perm())
		}
		return nil
	}))
	if relabel != nil {
		admission := admissionAt(filepath.Join(target, "admission.json"))
		relabel(admission)
		data, err := json.Marshal(admission)
		must(err)
		must(os.WriteFile(filepath.Join(target, "admission.json"), data, 0o600))
	}
}

func admissionAt(path string) map[string]any {
	data, err := os.ReadFile(path)
	must(err)
	var admission map[string]any
	must(json.Unmarshal(data, &admission))
	return admission
}

func setAside(host *oraclehost.Host) []map[string]any {
	paths, err := filepath.Glob(host.State("set-aside/swarm-*/admission.json"))
	must(err)
	asides := []map[string]any{}
	for _, path := range paths {
		asides = append(asides, admissionAt(path))
	}
	return asides
}

func rejoinedFrom(host *oraclehost.Host, previous, reason string) {
	asides := setAside(host)
	require(len(asides) == 1 && asides[0]["HostID"] == previous, "%s did not keep %s's swarm state aside: %v", host.Name, previous, asides)
	current := admissionAt(host.State("swarm/admission.json"))
	require(current["HostID"] == host.Name && current["InstanceID"] == host.InstanceID && current["FounderID"] != host.Name && current["Role"] == "container",
		"%s did not join its region's live cluster as itself: %v", host.Name, current)
	journal, err := os.ReadFile(filepath.Join(host.Dir, "journal.log"))
	must(err)
	require(strings.Contains(string(journal), reason) && strings.Contains(string(journal), "set aside the stored cluster state at"), "%s journal does not say why it set %s's state aside", host.Name, previous)
}

func restartResumes(ctx context.Context, host *oraclehost.Host, revision string) {
	before := admissionAt(host.State("swarm/admission.json"))
	run := host.LastRun()
	must(host.Restart())
	_, err := host.WaitReady(ctx, run, revision)
	must(err)
	after := admissionAt(host.State("swarm/admission.json"))
	require(len(setAside(host)) == 1 && after["FounderID"] == before["FounderID"] && after["HostID"] == host.Name, "%s's restart did not resume its own admission: %v", host.Name, after)
}
