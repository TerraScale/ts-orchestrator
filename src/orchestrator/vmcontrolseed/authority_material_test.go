package vmcontrolseed

import (
	"bytes"
	"encoding/json/v2"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
)

func TestOrdinaryAuthorityPinsIndependentRootMaterialToHostManifest(t *testing.T) {
	seeds, err := GenerateGRU("reader-source", []Guest{{ID: "gru-1", Address: "10.77.0.10", MembershipPublicKey: membershipPublic(t)}})
	if err != nil {
		t.Fatal(err)
	}
	seed := seeds["gru-1"]
	defer seed.Clear()
	reader, err := seed.AuthorityReader()
	if err != nil {
		t.Fatal(err)
	}
	material := &AuthorityMaterial{HostID: "sfo-2", Reader: reader, Files: map[string][]byte{}}
	for _, path := range []string{reader.NKeySeedFile, reader.CAFile, reader.CertificateFile, reader.KeyFile} {
		material.Files[path] = bytes.Clone(seed.Files[path])
	}
	defer material.Clear()
	pin, err := material.ReaderSHA256()
	if err != nil {
		t.Fatal(err)
	}
	settings, err := json.Marshal(map[string]string{NodeAuthorityReaderSHA256Setting: pin, "TS_ORCH_INSTANCE": "sfo-2"})
	if err != nil {
		t.Fatal(err)
	}
	manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{{Name: "orchestrator", Version: "1.0.0", ArtifactURL: "https://releases.terrascale.tech/orchestrator", SignatureURL: "https://releases.terrascale.tech/orchestrator.sig", Sha256: strings.Repeat("a", 64), User: ServiceUser, DataVolume: "/var/lib/terrascale/orchestrator", CPUWeight: 100, MemoryMaxBytes: 128 << 20, IOWeight: 100, Arguments: RunArguments, Configuration: string(settings)}}}
	if err := material.ValidateManifest("sfo-2", manifest); err != nil {
		t.Fatal(err)
	}
	if err := material.ValidateManifest("fra-2", manifest); err == nil {
		t.Fatal("reader accepted on a different host")
	}
	copied := material.Clone()
	defer copied.Clear()
	copied.Reader.Account = "other-account"
	if err := copied.ValidateManifest("sfo-2", manifest); err == nil {
		t.Fatal("changed public reader config was not rejected by signed pin")
	}
	copied = material.Clone()
	defer copied.Clear()
	copied.Files[reader.KeyFile] = bytes.Clone(seed.Files[PrivateKeyPath])
	if err := copied.Validate(); err == nil {
		t.Fatal("mismatched private reader identity accepted")
	}
}
