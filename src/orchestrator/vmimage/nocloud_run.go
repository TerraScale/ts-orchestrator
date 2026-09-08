package vmimage

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"maps"
	"slices"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
)

// Candidate preparation and fresh ordinary hosts keep their distinct finite
// owner admissions; neither is represented by fabricated initial GRU material.
func canonicalOrdinaryRunBootstrap(input TSNodeBootstrap) ([]NoCloudRootFile, error) {
	if input.ControllerRun == nil || input.InitialGrant == nil || input.Controller != nil {
		return nil, errors.New("vmimage: ordinary run requires finite owner admission")
	}
	manifest, err := hostmanifest.ParseHostManifest(input.DesiredHostManifest)
	if err != nil {
		return nil, err
	}
	if input.Candidate != nil {
		if err := input.ControllerRun.ValidatePredecessor(input.Config.NodeID, manifest); err != nil {
			return nil, err
		}
	} else if err := input.ControllerRun.ValidateManifest(input.Config.NodeID, manifest); err != nil {
		return nil, err
	}
	files := make([]NoCloudRootFile, 0, len(input.ControllerRun.Files))
	for _, path := range slices.Sorted(maps.Keys(input.ControllerRun.Files)) {
		raw := input.ControllerRun.Files[path]
		files = append(files, NoCloudRootFile{Path: path, Owner: vmcontrolseed.ServiceUser, Mode: 0400, Content: bytes.Clone(raw), runPath: path, runDigest: sha256.Sum256(raw)})
	}
	return files, nil
}
