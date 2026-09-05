package ocireconcile

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// BootstrapHostFile is explicit owner-provisioned node configuration. Secret
// values are excluded: user-data carries public Vault version references.
// Root-only file permissions do not make OCI metadata a secret store.
type BootstrapHostFile struct {
	Path    string
	Content []byte
	Private bool
}

func TSNodeCloudInit(version, digest, artifactURL, signatureURL, releasePublicKey string, files []BootstrapHostFile) (string, error) {
	encoded, err := renderTSNodeCloudInit(version, digest, artifactURL, signatureURL, releasePublicKey)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	ordered := append([]BootstrapHostFile(nil), files...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	seen := map[string]bool{}
	var declarations strings.Builder
	for _, file := range ordered {
		if !filepath.IsAbs(file.Path) || filepath.Clean(file.Path) != file.Path || (!strings.HasPrefix(file.Path, "/etc/terrascale/") && file.Path != "/var/lib/terrascale/ts-node/manifest.json") || strings.ContainsAny(file.Path, "\r\n\x00 :'") || seen[file.Path] || len(file.Content) == 0 || len(file.Content) > bootstrapHostFileLimit || file.Path == "/etc/terrascale/ts-node.pub" {
			return "", errors.New("provider: invalid initial host file")
		}
		seen[file.Path] = true
		mode := "0644"
		if file.Private {
			mode = "0600"
		}
		encoding, content, err := encodeBootstrapHostFile(file.Content)
		if err != nil {
			return "", err
		}
		declarations.WriteString("  - path: " + file.Path + "\n    owner: root:root\n    permissions: '" + mode + "'\n    encoding: " + encoding + "\n    content: " + content + "\n")
	}
	if !seen["/etc/terrascale/ts-node.json"] || !seen["/var/lib/terrascale/ts-node/manifest.json"] {
		return "", errors.New("provider: per-host node configuration and manifest are required")
	}
	rendered := strings.Replace(string(raw), "runcmd:\n", declarations.String()+"runcmd:\n", 1)
	result := base64.StdEncoding.EncodeToString([]byte(rendered))
	if len(result) > bootstrapMetadataLimit {
		return "", errors.New("provider: initial host configuration exceeds OCI metadata bound")
	}
	return result, nil
}

func validateBootstrapHostCloudInit(input map[int]string, count int) error {
	if len(input) == 0 {
		return &errs.Argument{Message: "initial per-slot host seeds are required"}
	}
	if len(input) != count {
		return errors.New("provider: every member slot requires its own initial configuration")
	}
	for index := 1; index <= count; index++ {
		encoded := input[index]
		if len(encoded) > bootstrapMetadataLimit {
			return errors.New("provider: invalid per-slot cloud-init")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(encoded) > bootstrapMetadataLimit || !strings.HasPrefix(string(raw), "#cloud-config\n") {
			return errors.New("provider: invalid per-slot cloud-init")
		}
		var document struct {
			Files []struct {
				Path     string `yaml:"path"`
				Encoding string `yaml:"encoding"`
				Content  string `yaml:"content"`
			} `yaml:"write_files"`
		}
		if err := yaml.Unmarshal(raw, &document); err != nil {
			return errors.New("provider: malformed per-slot cloud-init")
		}
		required := map[string]bool{"/etc/terrascale/ts-node.json": false, "/var/lib/terrascale/ts-node/manifest.json": false}
		seen := map[string]bool{}
		for _, file := range document.Files {
			if seen[file.Path] {
				return errors.New("provider: duplicate initial host file")
			}
			seen[file.Path] = true
			if _, ok := required[file.Path]; !ok {
				if file.Encoding != "" {
					if _, err := decodeBootstrapHostFile(file.Encoding, file.Content); err != nil {
						return err
					}
				}
				continue
			}
			content, err := decodeBootstrapHostFile(file.Encoding, file.Content)
			var object map[string]json.RawMessage
			if err != nil || json.Unmarshal(content, &object) != nil || object == nil {
				return errors.New("provider: initial node configuration and manifest must be bounded encoded JSON objects")
			}
			required[file.Path] = true
		}
		for _, present := range required {
			if !present {
				return errors.New("provider: initial node configuration and manifest are required at launch")
			}
		}
	}
	return nil
}

const bootstrapMetadataLimit = 48 * 1024
const bootstrapHostFileLimit = 32 * 1024

// Compress only when it reduces the serialized cloud-init representation.
func encodeBootstrapHostFile(content []byte) (string, string, error) {
	plain := base64.StdEncoding.EncodeToString(content)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(content); err != nil {
		return "", "", err
	}
	if err := writer.Close(); err != nil {
		return "", "", err
	}
	encoded := base64.StdEncoding.EncodeToString(compressed.Bytes())
	if len(encoded)+len("gz+b64") < len(plain)+len("b64") {
		return "gz+b64", encoded, nil
	}
	return "b64", plain, nil
}

// Accept one complete gzip member only and bound allocation before inflation.
func decodeBootstrapHostFile(encoding, content string) ([]byte, error) {
	invalid := errors.New("provider: invalid bounded host file encoding")
	if len(content) > base64.StdEncoding.EncodedLen(bootstrapHostFileLimit) {
		return nil, invalid
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(content)
	if err != nil {
		return nil, invalid
	}
	switch encoding {
	case "b64":
		if len(raw) == 0 || len(raw) > bootstrapHostFileLimit {
			return nil, invalid
		}
		return raw, nil
	case "gz+b64":
		source := bytes.NewReader(raw)
		reader, err := gzip.NewReader(source)
		if err != nil {
			return nil, invalid
		}
		reader.Multistream(false)
		decoded, readErr := io.ReadAll(io.LimitReader(reader, bootstrapHostFileLimit+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || len(decoded) == 0 || len(decoded) > bootstrapHostFileLimit || source.Len() != 0 {
			return nil, invalid
		}
		return decoded, nil
	default:
		return nil, invalid
	}
}
