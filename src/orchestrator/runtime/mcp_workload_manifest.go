// This file ports Runtime/Mcp/McpWorkloadManifest.cs.
package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// McpWorkloadManifest is the typed desired-state manifest of the MCP workload.
// Every field is closed: one qualified digest/architecture pair, the single
// admitted listener port, approved configuration keys only, secret references
// only, and the admitted probe paths.
type McpWorkloadManifest struct {
	ArtifactDigest   string
	Architecture     HostArchitecture
	HttpListenerPort int
	Configuration    map[string]string
	SecretReferences []McpSecretReference
	ProbePaths       []string
}

// McpAdmissionCode is the stable, redacted admission vocabulary.
type McpAdmissionCode int

const (
	McpAdmissionCodeAdmitted McpAdmissionCode = iota
	McpAdmissionCodeDocumentInvalid
	McpAdmissionCodeFieldUnknown
	McpAdmissionCodeAmbiguousContent
	McpAdmissionCodeFieldMissing
	McpAdmissionCodeArtifactNotQualified
	McpAdmissionCodeArchitectureNotQualified
	McpAdmissionCodePortNotAdmitted
	McpAdmissionCodeConfigurationKeyNotAdmitted
	McpAdmissionCodeConfigurationValueRejected
	McpAdmissionCodeSecretReferenceNotAdmitted
	McpAdmissionCodeProbePathNotAdmitted
)

func (c McpAdmissionCode) String() string {
	names := [...]string{
		"Admitted", "DocumentInvalid", "FieldUnknown", "AmbiguousContent", "FieldMissing",
		"ArtifactNotQualified", "ArchitectureNotQualified", "PortNotAdmitted",
		"ConfigurationKeyNotAdmitted", "ConfigurationValueRejected",
		"SecretReferenceNotAdmitted", "ProbePathNotAdmitted",
	}
	if c >= 0 && int(c) < len(names) {
		return names[c]
	}
	return fmt.Sprintf("McpAdmissionCode(%d)", int(c))
}

// McpAdmissionDecision is the bounded typed result of admitting one manifest.
type McpAdmissionDecision struct {
	Code   McpAdmissionCode
	Field  string
	Detail string
}

// IsAdmitted reports whether the decision is Admitted.
func (d McpAdmissionDecision) IsAdmitted() bool {
	return d.Code == McpAdmissionCodeAdmitted
}

// McpAdmissionDecisionAdmitted builds the admitted decision.
func McpAdmissionDecisionAdmitted() McpAdmissionDecision {
	return McpAdmissionDecision{Code: McpAdmissionCodeAdmitted}
}

func mcpReject(code McpAdmissionCode, field string, detail string) McpAdmissionDecision {
	return McpAdmissionDecision{Code: code, Field: field, Detail: detail}
}

// mcpWorkloadManifestDocument is the strict wire shape of one manifest
// document: nullable members mirror the C# nullability with pointers.
type mcpWorkloadManifestDocument struct {
	SchemaVersion    *mcpDocumentInt      `json:"schemaVersion"`
	Artifact         *mcpArtifactDocument `json:"artifact"`
	HttpListenerPort *mcpDocumentInt      `json:"httpListenerPort"`
	Configuration    map[string]*string   `json:"configuration"`
	SecretReferences []*string            `json:"secretReferences"`
	Probes           []*string            `json:"probes"`
}

type mcpArtifactDocument struct {
	Digest       *string `json:"digest"`
	Architecture *string `json:"architecture"`
}

// mcpDocumentInt mirrors the Web-defaults NumberHandling
// (AllowReadingFromString): numeric values may arrive as JSON strings.
type mcpDocumentInt struct {
	Value *int
}

func (d *mcpDocumentInt) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("null")) {
		d.Value = nil
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(trimmed, &text); err != nil {
			return err
		}
		parsed, err := strconv.Atoi(strings.TrimSpace(text))
		if err != nil {
			return err
		}
		d.Value = &parsed
		return nil
	}
	parsed, err := strconv.Atoi(string(trimmed))
	if err != nil {
		return err
	}
	d.Value = &parsed
	return nil
}

// McpWorkloadAdmission constants.
const (
	McpWorkloadAdmissionCurrentSchemaVersion            = 1
	McpWorkloadAdmissionMaximumDocumentCharacters       = 65_536
	McpWorkloadAdmissionMaximumConfigurationKeys        = 16
	McpWorkloadAdmissionMaximumConfigurationValueLength = 256
	McpWorkloadAdmissionMaximumSecretReferences         = 4
)

var mcpAllowedRootFields = map[string]bool{
	"schemaVersion": true, "artifact": true, "httpListenerPort": true,
	"configuration": true, "secretReferences": true, "probes": true,
}

var mcpAllowedArtifactFields = map[string]bool{
	"digest": true, "architecture": true,
}

// Generic workload-descriptor keys that must never be admitted through the
// typed MCP manifest seam. A document carrying any of them is rejected as
// ambiguous content before its typed values exist: the MCP workload runs the
// exact qualified artifact, not an operator-supplied image, executable, mount,
// capability, or environment payload.
var mcpGenericWorkloadFields = map[string]bool{
	"image": true, "images": true, "executable": true, "exec": true, "entrypoint": true,
	"command": true, "cmd": true, "args": true, "arguments": true,
	"mounts": true, "volumes": true, "devices": true, "hostPaths": true,
	"capabilities": true, "caps": true, "privileged": true,
	"environment": true, "env": true, "environmentFile": true, "user": true,
	"group": true, "workingDirectory": true, "shell": true,
	"ingress": true, "ingressHost": true, "dns": true, "hosts": true, "ports": true,
	"tlsCertificate": true, "certificate": true,
	"credentials": true, "secret": true, "secrets": true, "token": true, "apiKey": true,
}

// McpWorkloadAdmission ports the static McpWorkloadAdmission class (ADR 0032).
// A pure decision: no I/O, no mutation, no environment, no clock.
var McpWorkloadAdmission mcpWorkloadAdmission

type mcpWorkloadAdmission struct{}

// AdmitDocument admits a manifest document (the persisted/wire shape). It
// fails closed on any unknown field.
func (mcpWorkloadAdmission) AdmitDocument(document string, qualification *McpHttpArtifactQualification) McpAdmissionDecision {
	if qualification == nil {
		panic("qualification")
	}
	if strings.TrimSpace(document) == "" || len(document) > McpWorkloadAdmissionMaximumDocumentCharacters {
		return mcpReject(McpAdmissionCodeDocumentInvalid, "document",
			"The manifest document is empty or exceeds the document bound.")
	}
	if !json.Valid([]byte(document)) {
		return mcpReject(McpAdmissionCodeDocumentInvalid, "document",
			"The manifest document is not valid JSON.")
	}
	if trimmed := strings.TrimSpace(document); trimmed == "" || trimmed[0] != '{' {
		return mcpReject(McpAdmissionCodeDocumentInvalid, "document",
			"The manifest document must be a single JSON object.")
	}
	decoder := json.NewDecoder(strings.NewReader(document))
	decoder.UseNumber()
	violation, err := mcpScanElement(decoder, "", "")
	if err != nil {
		return mcpReject(McpAdmissionCodeDocumentInvalid, "document",
			"The manifest document is not valid JSON.")
	}
	if violation != nil {
		return *violation
	}

	var parsed mcpWorkloadManifestDocument
	if err := json.Unmarshal([]byte(document), &parsed); err != nil {
		return mcpReject(McpAdmissionCodeDocumentInvalid, "document",
			"The manifest document has an unexpected value type.")
	}

	if parsed.SchemaVersion == nil || parsed.SchemaVersion.Value == nil ||
		*parsed.SchemaVersion.Value != McpWorkloadAdmissionCurrentSchemaVersion {
		return mcpReject(McpAdmissionCodeDocumentInvalid, "schemaVersion",
			fmt.Sprintf("The manifest schema version must be %d.", McpWorkloadAdmissionCurrentSchemaVersion))
	}
	if parsed.Artifact == nil {
		return mcpReject(McpAdmissionCodeFieldMissing, "artifact",
			"The qualified artifact is required.")
	}
	if parsed.Artifact.Digest == nil || *parsed.Artifact.Digest == "" {
		return mcpReject(McpAdmissionCodeFieldMissing, "artifact.digest",
			"The artifact digest is required.")
	}
	if parsed.Artifact.Architecture == nil {
		return mcpReject(McpAdmissionCodeDocumentInvalid, "artifact.architecture",
			"The artifact architecture must be 'linux/arm64' or 'linux/amd64'.")
	}
	architecture, architectureOk := McpWorkloadAdmission.TryParseArchitecture(*parsed.Artifact.Architecture)
	if !architectureOk {
		return mcpReject(McpAdmissionCodeDocumentInvalid, "artifact.architecture",
			"The artifact architecture must be 'linux/arm64' or 'linux/amd64'.")
	}
	if parsed.HttpListenerPort == nil || parsed.HttpListenerPort.Value == nil {
		return mcpReject(McpAdmissionCodeFieldMissing, "httpListenerPort",
			"The fixed HTTP listener port is required.")
	}
	port := *parsed.HttpListenerPort.Value
	if parsed.SecretReferences == nil {
		return mcpReject(McpAdmissionCodeFieldMissing, "secretReferences",
			"The secret reference list is required.")
	}
	if len(parsed.SecretReferences) == 0 {
		return mcpReject(McpAdmissionCodeFieldMissing, "secretReferences",
			"The OAuth client secret reference is required by reference.")
	}
	if parsed.Probes == nil {
		return mcpReject(McpAdmissionCodeFieldMissing, "probes",
			"The admitted probe paths are required.")
	}

	configuration := make(map[string]string, len(parsed.Configuration))
	for key, value := range parsed.Configuration {
		if value == nil {
			return mcpReject(McpAdmissionCodeConfigurationValueRejected,
				"configuration."+key, "A configuration value is null.")
		}
		configuration[key] = *value
	}

	secretReferences := make([]McpSecretReference, 0, len(parsed.SecretReferences))
	for _, value := range parsed.SecretReferences {
		if value == nil {
			return mcpReject(McpAdmissionCodeDocumentInvalid, "secretReferences",
				"A secret reference is null.")
		}
		if !mcpSecretReferenceTokenPattern.MatchString(*value) {
			return mcpReject(McpAdmissionCodeSecretReferenceNotAdmitted, "secretReferences",
				"A secret reference must be a bounded 'vault:terrascale/mcp/<name>' token; "+
					"secret bytes are never admitted.")
		}
		reference, referenceErr := NewMcpSecretReference(*value)
		if referenceErr != nil {
			return mcpReject(McpAdmissionCodeSecretReferenceNotAdmitted, "secretReferences",
				fmt.Sprintf("The secret reference is not admitted; only '%s' may be referenced.",
					McpSecretReferenceNamesOAuthClientSecret))
		}
		secretReferences = append(secretReferences, reference)
	}

	probes := make([]string, 0, len(parsed.Probes))
	for _, value := range parsed.Probes {
		if value == nil {
			return mcpReject(McpAdmissionCodeDocumentInvalid, "probes",
				"A probe path is null.")
		}
		probes = append(probes, *value)
	}

	return McpWorkloadAdmission.AdmitManifest(McpWorkloadManifest{
		ArtifactDigest:   *parsed.Artifact.Digest,
		Architecture:     architecture,
		HttpListenerPort: port,
		Configuration:    configuration,
		SecretReferences: secretReferences,
		ProbePaths:       probes,
	}, qualification)
}

// AdmitManifest admits an already-typed manifest against the closed catalog
// and the qualification.
func (mcpWorkloadAdmission) AdmitManifest(manifest McpWorkloadManifest, qualification *McpHttpArtifactQualification) McpAdmissionDecision {
	if qualification == nil {
		panic("qualification")
	}

	digest := manifest.ArtifactDigest
	if len(digest) != McpQualifiedHttpArtifactDigestLength || !isLowercaseHexDigest(digest) {
		return mcpReject(McpAdmissionCodeArtifactNotQualified, "artifact.digest",
			"The artifact digest must be lowercase SHA-256 hex bound to a qualified artifact.")
	}
	if !manifest.Architecture.defined() {
		return mcpReject(McpAdmissionCodeDocumentInvalid, "artifact.architecture",
			"The artifact architecture is not admitted.")
	}
	if !qualification.AdmitsArchitecture(manifest.Architecture) {
		return mcpReject(McpAdmissionCodeArchitectureNotQualified, "artifact.architecture",
			"No qualified MCP HTTP artifact exists for this architecture.")
	}
	if !qualification.Admits(digest, manifest.Architecture) {
		return mcpReject(McpAdmissionCodeArtifactNotQualified, "artifact.digest",
			"The artifact digest is not the qualified digest for this architecture; "+
				"arbitrary images and executables are not admitted.")
	}

	if manifest.HttpListenerPort != McpWorkloadPortsHttpListenerPort {
		return mcpReject(McpAdmissionCodePortNotAdmitted, "httpListenerPort",
			fmt.Sprintf("The MCP workload listens on exactly port %d; no other port is admitted.",
				McpWorkloadPortsHttpListenerPort))
	}

	// A typed manifest with a nil collection is a malformed document, not an
	// exception: reject it with the same bounded vocabulary the document seam
	// uses (R8).
	if manifest.Configuration == nil {
		return mcpReject(McpAdmissionCodeFieldMissing, "configuration",
			"The configuration map is required (it may be empty).")
	}
	if manifest.SecretReferences == nil {
		return mcpReject(McpAdmissionCodeFieldMissing, "secretReferences",
			"The secret reference list is required.")
	}
	if manifest.ProbePaths == nil {
		return mcpReject(McpAdmissionCodeFieldMissing, "probes",
			"The probe path list is required.")
	}

	if len(manifest.Configuration) > McpWorkloadAdmissionMaximumConfigurationKeys {
		return mcpReject(McpAdmissionCodeConfigurationValueRejected, "configuration",
			fmt.Sprintf("The manifest carries more than %d configuration keys.",
				McpWorkloadAdmissionMaximumConfigurationKeys))
	}
	for _, key := range mcpSortedConfigurationKeys(manifest.Configuration) {
		value := manifest.Configuration[key]
		if !containsStringValue(McpConfigurationKeys.All, key) {
			return mcpReject(McpAdmissionCodeConfigurationKeyNotAdmitted, "configuration."+key,
				"The configuration key is not in the approved MCP configuration set.")
		}
		if value == "" || len(value) > McpWorkloadAdmissionMaximumConfigurationValueLength ||
			strings.ContainsFunc(value, unicode.IsControl) {
			return mcpReject(McpAdmissionCodeConfigurationValueRejected, "configuration."+key,
				"The configuration value is empty, unbounded, or carries control characters.")
		}
		if McpWorkloadAdmission.SecretBearingText(value) {
			return mcpReject(McpAdmissionCodeConfigurationValueRejected, "configuration."+key,
				"The configuration value appears to contain secret material; secrets travel by reference only.")
		}
		if containsStringValue(McpConfigurationKeys.HttpsUrlKeys, key) &&
			!isAbsoluteHttpsUrl(value) {
			return mcpReject(McpAdmissionCodeConfigurationValueRejected, "configuration."+key,
				"The URL-valued configuration must be an absolute HTTPS URL.")
		}
	}

	if len(manifest.SecretReferences) == 0 || len(manifest.SecretReferences) > McpWorkloadAdmissionMaximumSecretReferences {
		return mcpReject(McpAdmissionCodeSecretReferenceNotAdmitted, "secretReferences",
			"The manifest must carry at least the OAuth client secret reference and no more "+
				"than the admitted references.")
	}
	for _, reference := range manifest.SecretReferences {
		if reference.Name() != McpSecretReferenceNamesOAuthClientSecret {
			return mcpReject(McpAdmissionCodeSecretReferenceNotAdmitted, "secretReferences",
				fmt.Sprintf("Only the '%s' reference is admitted.",
					McpSecretReferenceNamesOAuthClientSecret))
		}
	}
	hasOAuthClientSecret := false
	for _, reference := range manifest.SecretReferences {
		if reference.Name() == McpSecretReferenceNamesOAuthClientSecret {
			hasOAuthClientSecret = true
			break
		}
	}
	if !hasOAuthClientSecret {
		return mcpReject(McpAdmissionCodeFieldMissing, "secretReferences",
			"The OAuth client secret reference is required by reference.")
	}

	if !stringSlicesEqual(manifest.ProbePaths, McpRouteContract.AdmittedProbePaths) {
		return mcpReject(McpAdmissionCodeProbePathNotAdmitted, "probes",
			fmt.Sprintf("The admitted probe paths are exactly %s.",
				strings.Join(McpRouteContract.AdmittedProbePaths, ", ")))
	}

	return McpAdmissionDecisionAdmitted()
}

// mcpScanElement ports ScanElement: the closed-field, duplicate and generic
// workload descriptor scan, in document order.
func mcpScanElement(decoder *json.Decoder, path string, parentField string) (*McpAdmissionDecision, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil, nil
	}
	switch delim {
	case '{':
		var allowed map[string]bool
		if parentField == "" {
			allowed = mcpAllowedRootFields
		} else if parentField == "artifact" {
			allowed = mcpAllowedArtifactFields
		}
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return nil, keyErr
			}
			key, isString := keyToken.(string)
			if !isString {
				return nil, fmt.Errorf("object key is not a string")
			}
			propertyPath := key
			if path != "" {
				propertyPath = path + "." + key
			}
			if seen[key] {
				decision := mcpReject(McpAdmissionCodeAmbiguousContent, propertyPath,
					"The property appears more than once.")
				return &decision, nil
			}
			seen[key] = true
			if mcpGenericWorkloadFields[key] {
				decision := mcpReject(McpAdmissionCodeAmbiguousContent, propertyPath,
					"Generic workload descriptor content is not admitted; "+
						"the MCP workload runs the exact qualified artifact only.")
				return &decision, nil
			}
			if allowed != nil && !allowed[key] {
				decision := mcpReject(McpAdmissionCodeFieldUnknown, propertyPath,
					"The field is not mapped by the MCP workload manifest contract.")
				return &decision, nil
			}
			nested, nestedErr := mcpScanElement(decoder, propertyPath, key)
			if nestedErr != nil {
				return nil, nestedErr
			}
			if nested != nil {
				return nested, nil
			}
		}
		if _, closeErr := decoder.Token(); closeErr != nil {
			return nil, closeErr
		}
	case '[':
		for decoder.More() {
			nested, nestedErr := mcpScanElement(decoder, path, parentField)
			if nestedErr != nil {
				return nil, nestedErr
			}
			if nested != nil {
				return nested, nil
			}
		}
		if _, closeErr := decoder.Token(); closeErr != nil {
			return nil, closeErr
		}
	}
	return nil, nil
}

func mcpSortedConfigurationKeys(configuration map[string]string) []string {
	keys := make([]string, 0, len(configuration))
	for key := range configuration {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// TryParseArchitecture maps the deployment-platform architecture string onto
// the host architecture the catalog admits. 'multi' is deliberately not
// admitted: the MCP artifact must be architecture-exact.
func (mcpWorkloadAdmission) TryParseArchitecture(value string) (HostArchitecture, bool) {
	switch value {
	case "linux/arm64":
		return HostArchitectureArm64, true
	case "linux/amd64":
		return HostArchitectureX64, true
	default:
		return HostArchitectureArm64, false
	}
}

var mcpSecretPattern = regexp.MustCompile(
	`(?i)(bearer\s+|(?:token|password|secret|private[_ -]?key|authorization)\s*[:=]|-----BEGIN)`)

// SecretBearingText reports whether the value appears to carry secret bytes.
func (mcpWorkloadAdmission) SecretBearingText(value string) bool {
	return mcpSecretPattern.MatchString(value)
}

func isAbsoluteHttpsUrl(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return false
	}
	return true
}
