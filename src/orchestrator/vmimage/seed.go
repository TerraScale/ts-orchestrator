package vmimage

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var instanceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// GuestArtifact is an exact production binary that the qualification guest
// receives through cloud-init or the test-only guest channel. Source is kept
// in the seed as provenance; the channel must still verify the bytes against
// SHA256 and Size before installing them.
type GuestArtifact struct {
	Component    string       `json:"component"`
	Architecture Architecture `json:"architecture"`
	Version      string       `json:"version"`
	Source       string       `json:"source"`
	SHA256       string       `json:"sha256"`
	Size         int64        `json:"size"`
	Mode         uint32       `json:"mode"`

	Sha256 string `json:"-"`
}

// BinaryArtifact is an alias used by callers that use “binary” rather than
// “guest artifact” terminology.
type BinaryArtifact = GuestArtifact

// GuestSeedSpec declares all values needed to make a reproducible guest seed.
// Exactly ts-node, orchestrator, and terrabase are required. Arbitrary
// components are rejected so a test cannot accidentally qualify a different
// production composition.
type GuestSeedSpec struct {
	Image        GuestImageManifest `json:"image"`
	Hostname     string             `json:"hostname"`
	InstanceID   string             `json:"instanceId"`
	Region       string             `json:"region"`
	DataDiskPath string             `json:"dataDiskPath"`
	Artifacts    []GuestArtifact    `json:"artifacts"`
}

// GuestChannelSeed is the canonical, opaque payload sent over the test-only
// guest control channel after systemd has booted. It contains no credentials
// and cannot authorize host mutations on its own.
type GuestChannelSeed struct {
	SchemaVersion int                `json:"schemaVersion"`
	Image         GuestImageManifest `json:"image"`
	Hostname      string             `json:"hostname"`
	InstanceID    string             `json:"instanceId"`
	Region        string             `json:"region"`
	DataDiskPath  string             `json:"dataDiskPath"`
	Artifacts     []GuestArtifact    `json:"artifacts"`
}

// BuildGuestChannelSeed produces stable JSON (including fixed artifact order)
// for the test-only channel. No download or installer is performed.
func BuildGuestChannelSeed(spec GuestSeedSpec) ([]byte, error) {
	seed, err := newGuestChannelSeed(spec)
	if err != nil {
		return nil, err
	}
	return json.Marshal(seed)
}

// BuildSeed is an alias for BuildGuestChannelSeed.
func BuildSeed(spec GuestSeedSpec) ([]byte, error) { return BuildGuestChannelSeed(spec) }

// BuildCloudInit creates deterministic cloud-config user data. The payload
// writes only the guest-channel declaration; artifact transfer and digest
// verification remain explicit test-controller operations, preserving the
// production ts-node path under test and avoiding shell interpolation.
func BuildCloudInit(spec GuestSeedSpec) ([]byte, error) {
	seed, err := newGuestChannelSeed(spec)
	if err != nil {
		return nil, err
	}
	seedBytes, err := json.Marshal(seed)
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(seedBytes)
	seedDigest := GuestChannelSeedDigest(seedBytes)
	var output bytes.Buffer
	output.WriteString("#cloud-config\n")
	output.WriteString("# terrascale guest-channel seed sha256: ")
	output.WriteString(seedDigest)
	output.WriteString("\n")
	for _, artifact := range seed.Artifacts {
		output.WriteString("# artifact ")
		output.WriteString(artifact.Component)
		output.WriteString(" version=")
		output.WriteString(artifact.Version)
		output.WriteString(" sha256=")
		output.WriteString(artifact.SHA256)
		output.WriteString("\n")
	}
	output.WriteString("preserve_hostname: true\n")
	output.WriteString("hostname: ")
	output.WriteString(yamlScalar(seed.Hostname))
	output.WriteString("\n")
	output.WriteString("manage_etc_hosts: true\n")
	output.WriteString("write_files:\n")
	output.WriteString("  - path: /run/terrascale/guest-seed.json\n")
	output.WriteString("    owner: root:root\n")
	output.WriteString("    permissions: '0600'\n")
	output.WriteString("    encoding: b64\n")
	output.WriteString("    content: ")
	output.WriteString(encoded)
	output.WriteString("\n")
	output.WriteString("runcmd:\n")
	output.WriteString("  - [systemctl, daemon-reload]\n")
	return output.Bytes(), nil
}

// BuildCloudInitSeed is a descriptive alias for BuildCloudInit.
func BuildCloudInitSeed(spec GuestSeedSpec) ([]byte, error) { return BuildCloudInit(spec) }

func newGuestChannelSeed(spec GuestSeedSpec) (GuestChannelSeed, error) {
	image, err := NewManifest(spec.Image)
	if err != nil {
		return GuestChannelSeed{}, err
	}
	if !namePattern.MatchString(spec.Hostname) || len(spec.Hostname) > 253 {
		return GuestChannelSeed{}, errors.New("vmimage: hostname is not a safe DNS name")
	}
	if !instanceIDPattern.MatchString(spec.InstanceID) {
		return GuestChannelSeed{}, errors.New("vmimage: instanceId is not safe")
	}
	if !namePattern.MatchString(spec.Region) || len(spec.Region) > 32 {
		return GuestChannelSeed{}, errors.New("vmimage: region is not a safe token")
	}
	if !validDataDiskPath(spec.DataDiskPath) {
		return GuestChannelSeed{}, errors.New("vmimage: dataDiskPath must be an absolute device or file path")
	}
	artifacts, err := canonicalGuestArtifacts(spec.Artifacts, image.Architecture)
	if err != nil {
		return GuestChannelSeed{}, err
	}
	return GuestChannelSeed{SchemaVersion: ManifestSchemaVersion, Image: image, Hostname: spec.Hostname, InstanceID: spec.InstanceID, Region: spec.Region, DataDiskPath: spec.DataDiskPath, Artifacts: artifacts}, nil
}

func canonicalGuestArtifacts(input []GuestArtifact, architecture Architecture) ([]GuestArtifact, error) {
	if len(input) != 3 {
		return nil, errors.New("vmimage: exactly ts-node, orchestrator, and terrabase artifacts are required")
	}
	byName := make(map[string]GuestArtifact, len(input))
	for _, artifact := range input {
		if artifact.Component != "ts-node" && artifact.Component != "orchestrator" && artifact.Component != "terrabase" {
			return nil, fmt.Errorf("vmimage: artifact component %q is not admitted", artifact.Component)
		}
		if _, exists := byName[artifact.Component]; exists {
			return nil, fmt.Errorf("vmimage: duplicate %s artifact", artifact.Component)
		}
		if artifact.Architecture != architecture {
			return nil, fmt.Errorf("vmimage: %s architecture does not match image", artifact.Component)
		}
		manifest := ArtifactManifest{Name: artifact.Component, Architecture: artifact.Architecture, Version: artifact.Version, Source: artifact.Source, SHA256: artifact.SHA256, Sha256: artifact.Sha256, Size: artifact.Size, Mode: artifact.Mode}
		if err := manifest.validate(artifact.Component, architecture, artifact.Version); err != nil {
			return nil, err
		}
		artifact.SHA256 = manifest.digest()
		artifact.Sha256 = ""
		artifact.Mode = manifest.expectedMode()
		byName[artifact.Component] = artifact
	}
	ordered := make([]GuestArtifact, 0, len(byName))
	for _, name := range []string{"ts-node", "orchestrator", "terrabase"} {
		artifact, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("vmimage: missing %s artifact", name)
		}
		ordered = append(ordered, artifact)
	}
	return ordered, nil
}

func validDataDiskPath(path string) bool {
	if path == "" || len(path) > 4096 || strings.ContainsRune(path, 0) || strings.Contains(path, "..") || !strings.HasPrefix(path, "/") {
		return false
	}
	return true
}

func yamlScalar(value string) string {
	// Hostname has already passed a conservative token validation. Single
	// quoting still makes the generated YAML unambiguous.
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// GuestChannelSeedDigest returns the digest used for readiness correlation.
func GuestChannelSeedDigest(seed []byte) string {
	sum := sha256.Sum256(seed)
	return hex.EncodeToString(sum[:])
}

// DecodeGuestChannelSeed strictly decodes a seed generated by this package.
func DecodeGuestChannelSeed(data []byte) (GuestChannelSeed, error) {
	if len(data) == 0 {
		return GuestChannelSeed{}, errors.New("vmimage: guest seed is empty")
	}
	if err := validateGuestChannelSeedJSON(data); err != nil {
		return GuestChannelSeed{}, fmt.Errorf("vmimage: decode guest seed: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var seed GuestChannelSeed
	if err := decoder.Decode(&seed); err != nil {
		return GuestChannelSeed{}, fmt.Errorf("vmimage: decode guest seed: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return GuestChannelSeed{}, errors.New("vmimage: guest seed has trailing data")
	}
	canonical, err := newGuestChannelSeed(GuestSeedSpec{Image: seed.Image, Hostname: seed.Hostname, InstanceID: seed.InstanceID, Region: seed.Region, DataDiskPath: seed.DataDiskPath, Artifacts: seed.Artifacts})
	if err != nil {
		return GuestChannelSeed{}, err
	}
	if seed.SchemaVersion != ManifestSchemaVersion {
		return GuestChannelSeed{}, errors.New("vmimage: unsupported guest seed schema")
	}
	return canonical, nil
}

type seedJSONObjectSchema struct {
	fields   map[string]seedJSONFieldSchema
	required []string
}

type seedJSONFieldSchema struct {
	object      *seedJSONObjectSchema
	objectArray *seedJSONObjectSchema
}

func validateGuestChannelSeedJSON(data []byte) error {
	transform := &seedJSONObjectSchema{
		fields: map[string]seedJSONFieldSchema{
			"type": {}, "sectorSize": {}, "startSector": {}, "sectorCount": {},
		},
		required: []string{"type", "sectorSize", "startSector", "sectorCount"},
	}
	manifestArtifact := &seedJSONObjectSchema{
		fields: map[string]seedJSONFieldSchema{
			"name": {}, "architecture": {}, "version": {}, "source": {},
			"sha256": {}, "size": {}, "mode": {}, "inputSha256": {},
			"inputSize": {}, "transform": {object: transform},
		},
		required: []string{"name", "architecture", "version", "source", "sha256", "size", "mode"},
	}
	image := &seedJSONObjectSchema{
		fields: map[string]seedJSONFieldSchema{
			"schemaVersion": {}, "ubuntuRelease": {}, "architecture": {},
			"version": {}, "kernel": {object: manifestArtifact},
			"rootfs": {object: manifestArtifact},
		},
		required: []string{"schemaVersion", "ubuntuRelease", "architecture", "version", "kernel", "rootfs"},
	}
	guestArtifact := &seedJSONObjectSchema{
		fields: map[string]seedJSONFieldSchema{
			"component": {}, "architecture": {}, "version": {}, "source": {},
			"sha256": {}, "size": {}, "mode": {},
		},
		required: []string{"component", "architecture", "version", "source", "sha256", "size", "mode"},
	}
	seed := &seedJSONObjectSchema{
		fields: map[string]seedJSONFieldSchema{
			"schemaVersion": {}, "image": {object: image}, "hostname": {},
			"instanceId": {}, "region": {}, "dataDiskPath": {},
			"artifacts": {objectArray: guestArtifact},
		},
		required: []string{"schemaVersion", "image", "hostname", "instanceId", "region", "dataDiskPath", "artifacts"},
	}
	return validateSeedJSONObjectDocument(data, seed, "seed")
}

func validateSeedJSONObjectDocument(data []byte, schema *seedJSONObjectSchema, path string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := validateSeedJSONObject(decoder, schema, path); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%s has trailing data", path)
	}
	return nil
}

func validateSeedJSONObject(decoder *json.Decoder, schema *seedJSONObjectSchema, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%s must be a JSON object: %w", path, err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("%s must be a non-null JSON object", path)
	}
	seen := make(map[string]bool, len(schema.fields))
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return fmt.Errorf("%s field name: %w", path, err)
		}
		name, ok := token.(string)
		if !ok {
			return fmt.Errorf("%s field name is invalid", path)
		}
		field, ok := schema.fields[name]
		if !ok {
			return fmt.Errorf("%s contains unknown field %q", path, name)
		}
		if seen[name] {
			return fmt.Errorf("%s contains duplicate field %q", path, name)
		}
		seen[name] = true

		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return fmt.Errorf("%s.%s: %w", path, name, err)
		}
		fieldPath := path + "." + name
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", fieldPath)
		}
		if field.object != nil {
			if err := validateSeedJSONObjectDocument(raw, field.object, fieldPath); err != nil {
				return err
			}
		}
		if field.objectArray != nil {
			if err := validateSeedJSONObjectArrayDocument(raw, field.objectArray, fieldPath); err != nil {
				return err
			}
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%s object is incomplete: %w", path, err)
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' {
		return fmt.Errorf("%s object is incomplete", path)
	}
	for _, name := range schema.required {
		if !seen[name] {
			return fmt.Errorf("%s is missing field %q", path, name)
		}
	}
	return nil
}

func validateSeedJSONObjectArrayDocument(data []byte, item *seedJSONObjectSchema, path string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%s must be a JSON array: %w", path, err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		return fmt.Errorf("%s must be a non-null JSON array", path)
	}
	index := 0
	for decoder.More() {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return fmt.Errorf("%s[%d]: %w", path, index, err)
		}
		itemPath := fmt.Sprintf("%s[%d]", path, index)
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", itemPath)
		}
		if err := validateSeedJSONObjectDocument(raw, item, itemPath); err != nil {
			return err
		}
		index++
	}
	closing, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%s array is incomplete: %w", path, err)
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != ']' {
		return fmt.Errorf("%s array is incomplete", path)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%s has trailing data", path)
	}
	return nil
}

// ArtifactComponents returns the fixed service order used by a guest seed.
func ArtifactComponents() []string { return []string{"ts-node", "orchestrator", "terrabase"} }
