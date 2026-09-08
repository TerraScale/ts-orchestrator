// Package runmaterial binds separately delivered production files to the signed
// run configuration through a content-addressed inventory.
package runmaterial

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"path/filepath"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

const Environment = "TS_ORCH_RUN_MATERIAL_FILE"
const Directory = "/etc/terrascale/orchestrator/run"
const MaximumFiles = 128
const MaximumFileBytes = 1 << 20

type inventory struct {
	Version int               `json:"version"`
	Files   map[string]string `json:"files"`
}

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func Build(files map[string][]byte) (string, []byte, error) {
	value := inventory{Version: 1, Files: map[string]string{}}
	if len(files) == 0 || len(files) > MaximumFiles {
		return "", nil, errors.New("runmaterial: invalid inventory bound")
	}
	for path, raw := range files {
		if !hostmanifest.SafeAbsolutePath(path) || len(raw) == 0 || len(raw) > MaximumFileBytes {
			return "", nil, errors.New("runmaterial: invalid protected file")
		}
		value.Files[path] = digest(raw)
	}
	raw, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return "", nil, err
	}
	return Directory + "/material-" + digest(raw) + ".json", raw, nil
}

// Verify reads through the existing descriptor-relative no-symlink reader. It
// hashes the bytes captured through each checked descriptor, never a later
// reopening after a separate path stat. All verification precedes startup.
func Verify(path string) error { return VerifySettings(path, nil) }

func VerifySettings(path string, settings map[string]string) error {
	bad := errors.New("runmaterial: signed protected material inventory verification failed")
	if !hostmanifest.SafeAbsolutePath(path) {
		return bad
	}
	name := filepath.Base(path)
	expected := strings.TrimSuffix(strings.TrimPrefix(name, "material-"), ".json")
	if name != "material-"+expected+".json" || !hostmanifest.ValidDigest(expected) {
		return bad
	}
	raw, err := initialgrant.ReadMaterialFile(path, 64<<10, true)
	if err != nil {
		return bad
	}
	defer clear(raw)
	if digest(raw) != expected {
		return bad
	}
	var value inventory
	if json.Unmarshal(raw, &value, json.RejectUnknownMembers(true)) != nil || value.Version != 1 || len(value.Files) == 0 || len(value.Files) > MaximumFiles {
		return bad
	}
	canonical, err := json.Marshal(value, json.Deterministic(true))
	if err != nil || string(canonical) != string(raw) {
		return bad
	}
	files := map[string][]byte{}
	defer func() {
		for _, raw := range files {
			clear(raw)
		}
	}()
	for target, want := range value.Files {
		if !hostmanifest.SafeAbsolutePath(target) || target == path || !hostmanifest.ValidDigest(want) {
			return bad
		}
		data, err := initialgrant.ReadMaterialFile(target, MaximumFileBytes, true)
		if err != nil {
			return bad
		}
		actual := digest(data)
		files[target] = data
		if actual != want {
			return bad
		}
	}
	return ValidateReferences(settings, files)
}
