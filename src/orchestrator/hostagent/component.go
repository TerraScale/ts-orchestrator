// This file defines the D-69 component vocabulary of the host agent: the
// desired-state component spec of the local manifest, the pinned-release
// manifest document ts-node watches, and the validation that keeps every
// value safe to embed in filesystem paths and systemd units.
package hostagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// TsNodeComponentName is the reserved component name of ts-node itself. Its
// unit follows the shared tsnodebootstrap contract and is never rewritten by
// the agent; only the current symlink flips under it.
const TsNodeComponentName = "ts-node"

// hostAgentNamePattern admits the canonical lowercase token with dot and dash
// separators — component names, versions, and unit users share it. Dots keep
// semver versions ("1.2.3") canonical; the pattern cannot produce a path
// escape or a systemd directive injection.
var hostAgentNamePattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)

// hostAgentSha256Pattern is the canonical lowercase SHA-256 hex digest.
var hostAgentSha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// hostAgentEd25519PublicKeyPattern is the canonical lowercase hex ed25519
// public key pinned in the agent configuration.
var hostAgentEd25519PublicKeyPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

const (
	hostAgentMaximumNameLength       = 63
	hostAgentMaximumUrlLength        = 2048
	hostAgentMaximumArtifactBytes    = 256 << 20
	hostAgentMaximumManifestBytes    = 1 << 20
	hostAgentMaximumManifestEntries  = 1024
	hostAgentMinimumCpuWeight        = 1
	hostAgentMaximumCpuWeight        = 10000
	hostAgentMinimumIoWeight         = 1
	hostAgentMaximumIoWeight         = 10000
	hostAgentMinimumMemoryMaxBytes   = 1 << 20
	hostAgentMaximumMemoryMaxBytes   = 1 << 46
	hostAgentReservedSystemGroupName = "root"
)

// requireHostAgentName enforces the shared canonical name vocabulary.
func requireHostAgentName(value, param, message string) (string, error) {
	if len(value) < 1 || len(value) > hostAgentMaximumNameLength ||
		!hostAgentNamePattern.MatchString(value) {
		return "", &errs.Argument{Param: param, Message: message}
	}
	return value, nil
}

// ComponentSpec is one desired component of the local manifest: where the
// signed release artifact comes from, the dedicated user and data volume its
// hardened unit runs under, and the cgroup v2 resource envelope D-69 pins in
// the unit file.
type ComponentSpec struct {
	// Name is the component token; it names /opt/terrascale/<name>/ and the
	// unit terrascale-<name>.service.
	Name string `json:"name"`
	// Version is the release version token of the desired artifact.
	Version string `json:"version"`
	// ArtifactURL is the https URL of the static release binary published by
	// ts-deploy.
	ArtifactURL string `json:"artifactUrl"`
	// SignatureURL is the https URL of the detached ed25519 signature over
	// the exact artifact bytes.
	SignatureURL string `json:"signatureUrl"`
	// Sha256 is the expected digest of the artifact bytes.
	Sha256 string `json:"sha256"`
	// User is the dedicated system account the unit runs as; never root.
	User string `json:"user"`
	// DataVolume is the absolute path of the one directory the unit may
	// write (ReadWritePaths); everything else is read-only.
	DataVolume string `json:"dataVolume"`
	// CPUWeight is the cgroup v2 CPUWeight of the unit (1..10000).
	CPUWeight int `json:"cpuWeight"`
	// MemoryMaxBytes is the cgroup v2 MemoryMax of the unit in bytes.
	MemoryMaxBytes int64 `json:"memoryMaxBytes"`
	// IOWeight is the cgroup v2 IOWeight of the unit (1..10000).
	IOWeight int `json:"ioWeight"`
	// NeedsNetlink adds AF_NETLINK to RestrictAddressFamilies. No launch
	// component needs it; the switch exists so a future component that
	// enumerates interfaces through rtnetlink can be admitted without
	// weakening every other unit.
	NeedsNetlink bool `json:"needsNetlink"`
}

// NewComponentSpec validates one component spec at the manifest trust
// boundary.
func NewComponentSpec(spec ComponentSpec) (ComponentSpec, error) {
	name, err := requireHostAgentName(spec.Name, "name",
		"Component name must be a lowercase token with dot or dash separators.")
	if err != nil {
		return ComponentSpec{}, err
	}
	version, err := requireHostAgentName(spec.Version, "version",
		"Component version must be a lowercase token with dot or dash separators.")
	if err != nil {
		return ComponentSpec{}, err
	}
	if err := requireHttpsArtifactURL(spec.ArtifactURL, "artifactUrl"); err != nil {
		return ComponentSpec{}, err
	}
	if err := requireHttpsArtifactURL(spec.SignatureURL, "signatureUrl"); err != nil {
		return ComponentSpec{}, err
	}
	if !hostAgentSha256Pattern.MatchString(spec.Sha256) {
		return ComponentSpec{}, &errs.Argument{
			Param:   "sha256",
			Message: "Component sha256 must be canonical lowercase SHA-256 hex.",
		}
	}
	user, err := requireHostAgentName(spec.User, "user",
		"Component user must be a lowercase token with dot or dash separators.")
	if err != nil {
		return ComponentSpec{}, err
	}
	if user == hostAgentReservedSystemGroupName || user == TsNodeComponentName {
		return ComponentSpec{}, &errs.Argument{
			Param:   "user",
			Message: "Component user must be a dedicated account, never root or ts-node.",
		}
	}
	if !safeAbsolutePath(spec.DataVolume) || strings.ContainsAny(spec.DataVolume, " \t\n\r\x00\\") ||
		len(spec.DataVolume) > 4096 {
		return ComponentSpec{}, &errs.Argument{
			Param:   "dataVolume",
			Message: "Component data volume must be a bounded absolute path.",
		}
	}
	if spec.CPUWeight < hostAgentMinimumCpuWeight || spec.CPUWeight > hostAgentMaximumCpuWeight {
		return ComponentSpec{}, &errs.ArgumentOutOfRangeError{
			Param: "cpuWeight",
			Message: fmt.Sprintf("CPUWeight must be between %d and %d.",
				hostAgentMinimumCpuWeight, hostAgentMaximumCpuWeight),
		}
	}
	if spec.MemoryMaxBytes < hostAgentMinimumMemoryMaxBytes ||
		spec.MemoryMaxBytes > hostAgentMaximumMemoryMaxBytes {
		return ComponentSpec{}, &errs.ArgumentOutOfRangeError{
			Param: "memoryMaxBytes",
			Message: fmt.Sprintf("MemoryMax must be between %d and %d bytes.",
				hostAgentMinimumMemoryMaxBytes, hostAgentMaximumMemoryMaxBytes),
		}
	}
	if spec.IOWeight < hostAgentMinimumIoWeight || spec.IOWeight > hostAgentMaximumIoWeight {
		return ComponentSpec{}, &errs.ArgumentOutOfRangeError{
			Param: "ioWeight",
			Message: fmt.Sprintf("IOWeight must be between %d and %d.",
				hostAgentMinimumIoWeight, hostAgentMaximumIoWeight),
		}
	}
	return ComponentSpec{
		Name:           name,
		Version:        version,
		ArtifactURL:    spec.ArtifactURL,
		SignatureURL:   spec.SignatureURL,
		Sha256:         spec.Sha256,
		User:           user,
		DataVolume:     spec.DataVolume,
		CPUWeight:      spec.CPUWeight,
		MemoryMaxBytes: spec.MemoryMaxBytes,
		IOWeight:       spec.IOWeight,
		NeedsNetlink:   spec.NeedsNetlink,
	}, nil
}

// requireHttpsArtifactURL admits exactly one bounded https URL without user
// info or embedded control characters, the shape ts-deploy release artifacts
// are published at.
func requireHttpsArtifactURL(value, param string) error {
	if value == "" || len(value) > hostAgentMaximumUrlLength ||
		strings.ContainsAny(value, "\r\n\x00") {
		return &errs.Argument{
			Param:   param,
			Message: "The release URL must be a bounded https URL.",
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.Hostname() == "" || strings.ContainsAny(parsed.Path, "\r\n\x00") {
		return &errs.Argument{
			Param:   param,
			Message: "The release URL must be a plain https URL without credentials.",
		}
	}
	return nil
}

// HostManifest is the desired component state ts-node watches. The
// orchestrator's delivery lane owns its content; ts-node only reconciles
// toward it.
type HostManifest struct {
	// Components are the desired components of this host.
	Components []ComponentSpec `json:"components"`
}

// CanonicalHostManifestJSON validates and returns the one compact JSON
// spelling used for durable publication and digest comparison.
func CanonicalHostManifestJSON(manifest HostManifest) ([]byte, error) {
	components, err := validateComponentSet(manifest.Components)
	if err != nil {
		return nil, err
	}
	return json.Marshal(HostManifest{Components: components})
}

// HostManifestSha256 returns the lowercase digest of canonical manifest JSON.
func HostManifestSha256(manifest HostManifest) (string, error) {
	canonical, err := CanonicalHostManifestJSON(manifest)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

// ParseHostManifest decodes and validates one manifest document, rejecting
// unknown fields, duplicate component names, and any invalid spec. The
// reserved ts-node self-component is admitted: its artifact is installed and
// its current symlink flipped like any other, but its unit is never written.
func ParseHostManifest(data []byte) (HostManifest, error) {
	if len(data) > hostAgentMaximumManifestBytes {
		return HostManifest{}, &InvalidDataError{Message: "The manifest exceeds its size bound."}
	}
	if err := validateHostManifestJSON(data); err != nil {
		return HostManifest{}, &InvalidDataError{Message: fmt.Sprintf(
			"The manifest is not the canonical JSON shape: %s.", err.Error())}
	}
	var wire struct {
		Components []ComponentSpec `json:"components"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return HostManifest{}, &InvalidDataError{Message: fmt.Sprintf(
			"The manifest is not the canonical JSON shape: %s.", err.Error())}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return HostManifest{}, &InvalidDataError{Message: "The manifest must be exactly one JSON document."}
	}
	if len(wire.Components) > hostAgentMaximumManifestEntries {
		return HostManifest{}, &InvalidDataError{Message: "The manifest contains too many components."}
	}
	components, err := validateComponentSet(wire.Components)
	if err != nil {
		return HostManifest{}, err
	}
	return HostManifest{Components: components}, nil
}

// validateComponentSet enforces the invariants that only exist across a
// whole manifest. Every component owns a distinct account and a disjoint
// writable tree.
func validateComponentSet(specs []ComponentSpec) ([]ComponentSpec, error) {
	if len(specs) > hostAgentMaximumManifestEntries {
		return nil, &InvalidDataError{Message: "The manifest contains too many components."}
	}
	names := make(map[string]struct{}, len(specs))
	users := make(map[string]string, len(specs))
	validated := make([]ComponentSpec, 0, len(specs))
	for _, spec := range specs {
		component, err := NewComponentSpec(spec)
		if err != nil {
			return nil, err
		}
		if _, duplicate := names[component.Name]; duplicate {
			return nil, &InvalidDataError{Message: fmt.Sprintf(
				"The manifest names component %q twice.", component.Name)}
		}
		if owner, duplicate := users[component.User]; duplicate {
			return nil, &InvalidDataError{Message: fmt.Sprintf(
				"Components %q and %q cannot share dedicated user %q.", owner, component.Name, component.User)}
		}
		for _, existing := range validated {
			if pathsOverlap(existing.DataVolume, component.DataVolume) {
				return nil, &InvalidDataError{Message: fmt.Sprintf(
					"Component data volumes %q and %q overlap.", existing.DataVolume, component.DataVolume)}
			}
		}
		names[component.Name] = struct{}{}
		users[component.User] = component.Name
		validated = append(validated, component)
	}
	return validated, nil
}

func pathsOverlap(first, second string) bool {
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	if first == second {
		return true
	}
	separator := string(filepath.Separator)
	return strings.HasPrefix(first, second+separator) || strings.HasPrefix(second, first+separator)
}

type hostManifestJSONField struct {
	objectArray bool
}

func validateHostManifestJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := validateHostManifestObject(decoder, "manifest", map[string]hostManifestJSONField{
		"components": {objectArray: true},
	}, []string{"components"}); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("manifest contains trailing data")
	}
	return nil
}

func validateHostManifestObject(decoder *json.Decoder, path string, fields map[string]hostManifestJSONField, required []string) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%s must be an object: %w", path, err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("%s must be a non-null object", path)
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%s field name: %w", path, err)
		}
		name, ok := nameToken.(string)
		if !ok {
			return fmt.Errorf("%s field name is invalid", path)
		}
		field, known := fields[name]
		if !known {
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
		if field.objectArray {
			if err := validateHostManifestComponents(raw, fieldPath); err != nil {
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
	for _, name := range required {
		if !seen[name] {
			return fmt.Errorf("%s is missing field %q", path, name)
		}
	}
	return nil
}

func validateHostManifestComponents(data []byte, path string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%s must be an array: %w", path, err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		return fmt.Errorf("%s must be a non-null array", path)
	}
	fields := map[string]hostManifestJSONField{
		"name": {}, "version": {}, "artifactUrl": {}, "signatureUrl": {},
		"sha256": {}, "user": {}, "dataVolume": {}, "cpuWeight": {},
		"memoryMaxBytes": {}, "ioWeight": {}, "needsNetlink": {},
	}
	required := []string{
		"name", "version", "artifactUrl", "signatureUrl", "sha256", "user",
		"dataVolume", "cpuWeight", "memoryMaxBytes", "ioWeight", "needsNetlink",
	}
	index := 0
	for decoder.More() {
		if index >= hostAgentMaximumManifestEntries {
			return fmt.Errorf("%s contains too many components", path)
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return fmt.Errorf("%s[%d]: %w", path, index, err)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s[%d] must not be null", path, index)
		}
		itemDecoder := json.NewDecoder(bytes.NewReader(raw))
		if err := validateHostManifestObject(itemDecoder, fmt.Sprintf("%s[%d]", path, index), fields, required); err != nil {
			return err
		}
		var trailing any
		if err := itemDecoder.Decode(&trailing); err != io.EOF {
			return fmt.Errorf("%s[%d] contains trailing data", path, index)
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
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("%s contains trailing data", path)
	}
	return nil
}
