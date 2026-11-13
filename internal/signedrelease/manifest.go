package signedrelease

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/sshsig"
	"golang.org/x/crypto/ssh"
)

const Namespace = "ts-orch-release"

type Binary struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	V        int               `json:"v"`
	Channel  string            `json:"channel"`
	Sequence uint64            `json:"sequence"`
	SHA      string            `json:"sha"`
	Created  int64             `json:"created"`
	Binaries map[string]Binary `json:"binaries"`
}

var (
	shaPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	downloadPrefix = "https://github.com/TerraScale/ts-orchestrator/releases/download/"
	manifestArchs  = []string{"linux/amd64", "linux/arm64"}
)

func Decode(data []byte) (Manifest, error) {
	var m Manifest
	if err := decodeStrict(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("signedrelease: manifest: %w", err)
	}
	if err := validateManifestKeys(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return Manifest{}, fmt.Errorf("signedrelease: manifest: %w", err)
	}
	if m.V != 1 {
		return Manifest{}, fmt.Errorf("signedrelease: manifest v%d is not 1", m.V)
	}
	if m.Channel != "production" {
		return Manifest{}, fmt.Errorf("signedrelease: manifest channel %q is not production", m.Channel)
	}
	if m.Sequence == 0 {
		return Manifest{}, errors.New("signedrelease: manifest sequence is zero")
	}
	if !shaPattern.MatchString(m.SHA) {
		return Manifest{}, fmt.Errorf("signedrelease: manifest sha %q is not a 40-hex commit", m.SHA)
	}
	if m.Created <= 0 {
		return Manifest{}, errors.New("signedrelease: manifest creation time must be positive")
	}
	if len(m.Binaries) != len(manifestArchs) {
		return Manifest{}, errors.New("signedrelease: manifest binaries must cover exactly linux/amd64 and linux/arm64")
	}
	for _, osArch := range manifestArchs {
		b, ok := m.Binaries[osArch]
		if !ok {
			return Manifest{}, fmt.Errorf("signedrelease: manifest is missing the %s binary", osArch)
		}
		if !strings.HasPrefix(b.URL, downloadPrefix) {
			return Manifest{}, fmt.Errorf("signedrelease: %s url %q is not a ts-orchestrator release download", osArch, b.URL)
		}
		if !sha256Pattern.MatchString(b.SHA256) {
			return Manifest{}, fmt.Errorf("signedrelease: %s sha256 %q is not 64 lower-case hex", osArch, b.SHA256)
		}
	}
	return m, nil
}

func validateManifestKeys(dec *json.Decoder, level int) error {
	fields := []string{"v", "channel", "sequence", "sha", "created", "binaries"}
	if level == 1 {
		fields = manifestArchs
	} else if level == 2 {
		fields = []string{"url", "sha256"}
	}
	start, err := dec.Token()
	if err != nil {
		return err
	}
	if start != json.Delim('{') {
		return errors.New("expected a manifest object")
	}
	seen := make(map[string]bool, len(fields))
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok || !slices.Contains(fields, key) {
			return fmt.Errorf("unexpected manifest key %q", token)
		}
		if seen[key] {
			return fmt.Errorf("duplicate manifest key %q", key)
		}
		seen[key] = true
		if level == 1 || level == 0 && key == "binaries" {
			if err := validateManifestKeys(dec, level+1); err != nil {
				return err
			}
		} else if _, err := dec.Token(); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	if len(seen) != len(fields) {
		return errors.New("missing manifest object key")
	}
	return nil
}

type AllowedKey struct {
	Name  string
	Key   ssh.PublicKey
	Roles []string
}

type allowedKeyEntry struct {
	Name  string   `json:"name"`
	Key   string   `json:"key"`
	Roles []string `json:"roles"`
}

type allowedKeysFile struct {
	Keys []allowedKeyEntry `json:"keys"`
}

func parseAllowed(data []byte) ([]AllowedKey, error) {
	var file allowedKeysFile
	if err := decodeStrict(data, &file); err != nil {
		return nil, fmt.Errorf("signedrelease: allowed keys: %w", err)
	}
	keys := make([]AllowedKey, 0, len(file.Keys))
	for _, entry := range file.Keys {
		parsed, err := sshsig.ParseAllowed([]string{entry.Key})
		if err != nil {
			return nil, fmt.Errorf("signedrelease: allowed key %s: %w", entry.Name, err)
		}
		keys = append(keys, AllowedKey{Name: entry.Name, Key: parsed[0], Roles: entry.Roles})
	}
	return keys, nil
}

func Allowed() ([]AllowedKey, error) {
	data, err := m1.Files.ReadFile("allowed-keys.json")
	if err != nil {
		return nil, fmt.Errorf("signedrelease: allowed keys: %w", err)
	}
	return parseAllowed(data)
}

func Verify(manifest, signature []byte) (Manifest, string, error) {
	keys, err := Allowed()
	if err != nil {
		return Manifest{}, "", err
	}
	return verifyWith(manifest, signature, keys)
}

func decodeStrict(data []byte, value any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("expected exactly one JSON value")
	}
	return nil
}

func verifyWith(manifest, signature []byte, all []AllowedKey) (Manifest, string, error) {
	var release []AllowedKey
	var pubs []ssh.PublicKey
	for _, k := range all {
		if slices.Contains(k.Roles, "release") {
			release = append(release, k)
			pubs = append(pubs, k.Key)
		}
	}
	if len(release) == 0 {
		return Manifest{}, "", errors.New("no allowed release keys")
	}
	m, err := Decode(manifest)
	if err != nil {
		return Manifest{}, "", err
	}
	pub, err := sshsig.Verify(manifest, signature, Namespace, pubs)
	if err != nil {
		return Manifest{}, "", err
	}
	for _, k := range release {
		if bytes.Equal(k.Key.Marshal(), pub.Marshal()) {
			return m, k.Name, nil
		}
	}
	return Manifest{}, "", errors.New("signedrelease: signer name not found")
}
