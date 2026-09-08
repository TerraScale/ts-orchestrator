package vmimage

import (
	"bytes"
	"errors"
	"maps"
	"slices"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
)

// The finite ordinary grant binds the public reader configuration. Its private
// credentials are consumed by root ts-node, outside the controller inventory.
func canonicalOrdinaryAuthorityBootstrap(input TSNodeBootstrap) ([]NoCloudRootFile, error) {
	m := input.OrdinaryAuthority
	if m == nil {
		if input.ControllerRun != nil && input.Controller == nil && input.Candidate == nil {
			return nil, errors.New("vmimage: ordinary run requires independent authority reader material")
		}
		return nil, nil
	}
	if input.Controller != nil || input.Candidate != nil || input.ControllerRun == nil || input.InitialGrant == nil {
		return nil, errors.New("vmimage: independent authority reader requires a finite ordinary run grant")
	}
	if m.Reader != input.Config.AuthorityReader {
		return nil, errors.New("vmimage: ordinary authority reader differs from ts-node configuration")
	}
	manifest, err := hostmanifest.ParseHostManifest(input.DesiredHostManifest)
	if err != nil {
		return nil, err
	}
	if err := m.ValidateManifest(input.Config.NodeID, manifest); err != nil {
		return nil, err
	}
	files := make([]NoCloudRootFile, 0, len(m.Files))
	for _, path := range slices.Sorted(maps.Keys(m.Files)) {
		files = append(files, NoCloudRootFile{Path: path, Mode: 0400, Content: bytes.Clone(m.Files[path])})
	}
	return files, nil
}
