package vmimage

import (
	"bytes"
	"errors"
	"sort"

	"terrascale.tech/orchestrator/src/orchestrator/vmcandidateseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
)

func canonicalCandidateBootstrap(input TSNodeBootstrap) ([]NoCloudRootFile, error) {
	if input.Candidate == nil {
		return nil, nil
	}
	bad := errors.New("vmimage: candidate material differs from owner-admitted image")
	m := input.Candidate
	if input.Controller != nil || input.InitialGrant == nil || m.Config.NodeID != input.Config.NodeID || m.Reader != input.Config.AuthorityReader || !bytes.Equal(m.PublicKeyPEM, input.InitialGrant.PublicKeyPEM) || !bytes.Equal(m.BootstrapGrant, input.InitialGrant.SignedGrant) {
		return nil, bad
	}
	if err := m.ValidateManifest(input.DesiredHostManifest); err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(m.Files))
	for path := range m.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	files := make([]NoCloudRootFile, 0, len(paths)+2)
	for _, path := range paths {
		owner := ""
		if vmcandidateseed.IsServiceFile(path) {
			owner = vmcontrolseed.ServiceUser
		}
		file := NoCloudRootFile{Path: path, Mode: 0400, Owner: owner, Content: append([]byte(nil), m.Files[path]...)}
		if err := file.Validate(); err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	for _, entry := range []struct {
		path string
		raw  []byte
	}{{vmcandidateseed.GrantPath, m.PreparationGrant}, {vmcandidateseed.OwnerPath, m.PublicKeyPEM}} {
		file := NoCloudRootFile{Path: entry.path, Mode: 0400, Owner: vmcontrolseed.ServiceUser, Content: append([]byte(nil), entry.raw...)}
		if err := file.Validate(); err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}
