package vmimage

import (
	"bytes"
	"encoding/json/v2"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
)

func ordinaryAuthorityFixture(t *testing.T) TSNodeBootstrap {
	t.Helper()
	input := candidateImageFixture(t)
	m := &vmcontrolseed.AuthorityMaterial{HostID: input.Config.NodeID, Reader: input.Config.AuthorityReader, Files: map[string][]byte{}}
	for path, raw := range input.Candidate.Files {
		if vmcontrolseed.IsAuthorityFilePath(path) {
			m.Files[path] = bytes.Clone(raw)
		}
	}
	t.Cleanup(m.Clear)
	pin, err := m.ReaderSHA256()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := hostmanifest.ParseHostManifest(input.DesiredHostManifest)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := json.Marshal(map[string]string{"TS_ORCH_INSTANCE": input.Config.NodeID, vmcontrolseed.NodeAuthorityReaderSHA256Setting: pin})
	if err != nil {
		t.Fatal(err)
	}
	manifest.Components[0].Arguments = vmcontrolseed.RunArguments
	manifest.Components[0].Configuration = string(settings)
	input.DesiredHostManifest, err = hostmanifest.CanonicalHostManifestJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	input.Candidate = nil
	input.ControllerRun = &vmcontrolseed.RunMaterial{}
	input.OrdinaryAuthority = m
	return input
}

func TestOrdinaryAuthoritySidebandStaysRootOnly(t *testing.T) {
	input := ordinaryAuthorityFixture(t)
	files, err := canonicalOrdinaryAuthorityBootstrap(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 || controllerOwnershipBootstrap(files) != "" {
		t.Fatal("ordinary reader credentials entered controller ownership")
	}
	for _, file := range files {
		if file.Owner != "" || file.Mode != 0400 || file.Validate() != nil || !bytes.Equal(file.Content, input.OrdinaryAuthority.Files[file.Path]) {
			t.Fatal("ordinary reader sideband is not private and exact")
		}
		file.Content[0] ^= 1
		if bytes.Equal(file.Content, input.OrdinaryAuthority.Files[file.Path]) {
			t.Fatal("sideband aliases producer material")
		}
	}
}

func TestOrdinaryAuthorityRejectsUnboundReader(t *testing.T) {
	for _, kind := range []string{"missing", "reader", "host", "pin", "credentials", "grant", "controller"} {
		t.Run(kind, func(t *testing.T) {
			input := ordinaryAuthorityFixture(t)
			switch kind {
			case "missing":
				input.OrdinaryAuthority = nil
			case "reader":
				input.Config.AuthorityReader.ServerName = "other"
			case "host":
				input.Config.NodeID = "sfo-other"
			case "pin":
				input.DesiredHostManifest = bytes.ReplaceAll(input.DesiredHostManifest, []byte(vmcontrolseed.NodeAuthorityReaderSHA256Setting), []byte("OTHER_PIN"))
			case "credentials":
				input.OrdinaryAuthority.Files[vmcontrolseed.AuthorityNKeyPath] = []byte("invalid")
			case "grant":
				input.InitialGrant = nil
			case "controller":
				input.Controller = &vmcontrolseed.Material{}
			}
			if _, err := canonicalOrdinaryAuthorityBootstrap(input); err == nil {
				t.Fatal("unbound ordinary reader accepted")
			}
		})
	}
}
