package hostmanifest

import (
	"encoding/json"
	"strings"
	"testing"
)

func testComponentSpec() ComponentSpec {
	return ComponentSpec{
		Name:           "terrabase",
		Version:        "1.2.3",
		ArtifactURL:    "https://releases.terrascale.tech/terrabase/1.2.3/terrabase",
		SignatureURL:   "https://releases.terrascale.tech/terrabase/1.2.3/terrabase.sig",
		Sha256:         strings.Repeat("0a", 32),
		User:           "terrascale-terrabase",
		DataVolume:     "/var/lib/terrascale/terrabase",
		CPUWeight:      200,
		MemoryMaxBytes: 8 << 30,
		IOWeight:       300,
	}
}

func componentJSON(t *testing.T, spec ComponentSpec) string {
	t.Helper()
	encoded, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
func TestParseHostManifestRejectsNonCanonicalJSON(t *testing.T) {
	spec := testComponentSpec()
	component := componentJSON(t, spec)
	valid := `{"components":[` + component + `]}`
	cases := map[string]string{
		"top-level null":      `null`,
		"components null":     `{"components":null}`,
		"component null":      `{"components":[null]}`,
		"top-level duplicate": `{"components":[],"components":[]}`,
		"top-level case":      strings.Replace(valid, `"components"`, `"Components"`, 1),
		"top-level unknown":   strings.Replace(valid, `{`, `{"unknown":true,`, 1),
		"trailing document":   valid + `{}`,
		"component duplicate": strings.Replace(valid, `"name":"terrabase"`, `"name":"terrabase","name":"terrabase"`, 1),
		"component case":      strings.Replace(valid, `"artifactUrl"`, `"ArtifactUrl"`, 1),
		"component unknown":   strings.Replace(valid, `"name":"terrabase"`, `"name":"terrabase","unknown":true`, 1),
		"component null field": strings.Replace(valid,
			`"dataVolume":"`+spec.DataVolume+`"`, `"dataVolume":null`, 1),
		"component missing field": strings.Replace(valid, `,"needsNetlink":false`, ``, 1),
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseHostManifest([]byte(document)); err == nil {
				t.Fatal("non-canonical manifest accepted")
			}
		})
	}
	if _, err := ParseHostManifest([]byte(valid)); err != nil {
		t.Fatalf("canonical manifest rejected: %v", err)
	}
	oversized := append([]byte(valid), []byte(strings.Repeat(" ", MaximumManifestBytes-len(valid)+1))...)
	if _, err := ParseHostManifest(oversized); err == nil {
		t.Fatal("oversized manifest accepted")
	}
}

func TestComponentLaunchRejectsInterpolationAndSecretKey(t *testing.T) {
	for _, arguments := range []string{"--config $PATH", "--config %i", "--config `whoami`", "--config \"file\"", "--config /tmp/a\nb", "--config  /tmp/a", "@config", "@config @config"} {
		spec := testComponentSpec()
		spec.Arguments = arguments
		if _, err := NewComponentSpec(spec); err == nil {
			t.Errorf("unsafe arguments accepted: %q", arguments)
		}
	}
	spec := testComponentSpec()
	spec.Arguments, spec.Configuration = "--config @config", "-----BEGIN PRIVATE KEY-----"
	if _, err := NewComponentSpec(spec); err == nil {
		t.Fatal("embedded key accepted")
	}
}

func TestApplyManifestCommandRetainsExactWireAdmission(t *testing.T) {
	manifest := HostManifest{Components: []ComponentSpec{testComponentSpec()}}
	command, err := NewApplyManifestCommand("apply-1", strings.Repeat("a", 64), manifest)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseApplyManifestCommand(wire)
	if err != nil || parsed.CommandId != command.CommandId {
		t.Fatalf("canonical command: %+v %v", parsed, err)
	}
	valid := string(wire)
	for name, bad := range map[string]string{
		"null": "null", "duplicate": strings.Replace(valid, `"commandId":"apply-1"`, `"commandId":"apply-1","commandId":"apply-1"`, 1),
		"case":                  strings.Replace(valid, `"commandId"`, `"CommandId"`, 1),
		"unknown":               strings.Replace(valid, `{`, `{"extra":1,`, 1),
		"missing":               strings.Replace(valid, `"commandId":"apply-1",`, "", 1),
		"null field":            strings.Replace(valid, `"commandId":"apply-1"`, `"commandId":null`, 1),
		"wrong type":            strings.Replace(valid, `"commandId":"apply-1"`, `"commandId":true`, 1),
		"noncanonical manifest": strings.Replace(valid, `"manifest":{`, `"manifest":{ `, 1),
		"trailing":              valid + "{}",
		"dotted command token":  strings.Replace(valid, "apply-1", "apply.1", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseApplyManifestCommand([]byte(bad)); err == nil {
				t.Fatal("invalid handoff accepted")
			}
		})
	}
}

func TestCanonicalManifestPreservesExistingWireDigest(t *testing.T) {
	manifest := HostManifest{Components: []ComponentSpec{testComponentSpec()}}
	canonical, err := CanonicalHostManifestJSON(manifest)
	if err != nil || string(canonical) != `{"components":[{"name":"terrabase","version":"1.2.3","artifactUrl":"https://releases.terrascale.tech/terrabase/1.2.3/terrabase","signatureUrl":"https://releases.terrascale.tech/terrabase/1.2.3/terrabase.sig","sha256":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a","user":"terrascale-terrabase","dataVolume":"/var/lib/terrascale/terrabase","cpuWeight":200,"memoryMaxBytes":8589934592,"ioWeight":300,"needsNetlink":false}]}` {
		t.Fatalf("canonical manifest changed: %s %v", canonical, err)
	}
	digest, err := HostManifestSha256(manifest)
	if err != nil || digest != "0977af5f7b9c127241116a9494299f80c88922bd6c60973c37f35841bc6d86a1" {
		t.Fatalf("manifest digest changed: %s %v", digest, err)
	}
}
