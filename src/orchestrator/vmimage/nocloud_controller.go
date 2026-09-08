package vmimage

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"maps"
	"slices"
	"sort"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"

	"terrascale.tech/orchestrator/src/orchestrator/vmcandidateseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
)

func canonicalControllerBootstrap(input TSNodeBootstrap) ([]NoCloudRootFile, error) {
	if input.Controller == nil {
		if input.ControllerRun != nil {
			return canonicalOrdinaryRunBootstrap(input)
		}
		return nil, nil
	}
	m := input.Controller
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if err := m.ValidateMembership(input.MembershipIdentityPrivateKey, input.MembershipPins); err != nil {
		return nil, err
	}
	reader, err := m.AuthorityReader()
	if err != nil {
		return nil, err
	}
	if reader != input.Config.AuthorityReader {
		return nil, errors.New("vmimage: authority reader differs from signed grant")
	}
	if m.HostID != input.Config.NodeID {
		return nil, errors.New("vmimage: controller material belongs to another host")
	}
	manifest, err := hostmanifest.ParseHostManifest(input.DesiredHostManifest)
	if err != nil {
		return nil, err
	}
	matched := false
	for _, component := range manifest.Components {
		if component.Name == "orchestrator" {
			matched = component.Arguments == vmcontrolseed.Arguments && component.Configuration == m.Settings
		}
	}
	if !matched {
		return nil, errors.New("vmimage: controller configuration does not match signed launch manifest")
	}
	paths := make([]string, 0, len(m.Files))
	for path := range m.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	files := make([]NoCloudRootFile, 0, len(paths))
	for _, path := range paths {
		owner := vmcontrolseed.ServiceUser
		if vmcontrolseed.IsAuthorityFilePath(path) {
			owner = ""
		}
		files = append(files, NoCloudRootFile{Path: path, Mode: 0400, Owner: owner, Content: append([]byte(nil), m.Files[path]...)})
	}
	if input.ControllerRun != nil {
		if err := input.ControllerRun.ValidateStage(*m, manifest); err != nil {
			return nil, err
		}
		for _, path := range slices.Sorted(maps.Keys(input.ControllerRun.Files)) {
			files = append(files, NoCloudRootFile{Path: path, Mode: 0400, Owner: vmcontrolseed.ServiceUser, Content: bytes.Clone(input.ControllerRun.Files[path]), runPath: path, runDigest: sha256.Sum256(input.ControllerRun.Files[path])})
		}
	}
	return files, nil
}

func controllerOwnershipBootstrap(files []NoCloudRootFile) string {
	var script strings.Builder
	for _, file := range files {
		if file.Owner != vmcontrolseed.ServiceUser && !vmcontrolseed.IsFilePath(file.Path) && !vmcandidateseed.IsServiceFile(file.Path) && !vmengineconfig.IsControlPath(file.Path) && !vmengineconfig.IsDatabasePath(file.Path) {
			continue
		}
		script.WriteString("/usr/bin/chown " + vmcontrolseed.ServiceUser + ":" + vmcontrolseed.ServiceUser + " " + file.Path + "\n")
		script.WriteString("/usr/bin/chmod 0400 " + file.Path + "\n")
		script.WriteString("/usr/bin/test \"$(/usr/bin/stat -c %U:%G:%a " + file.Path + ")\" = " + vmcontrolseed.ServiceUser + ":" + vmcontrolseed.ServiceUser + ":400\n")
	}
	return script.String()
}
