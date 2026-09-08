package authorizationlease

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRingRejectsAmbiguousOrUnboundedVerificationKeys(t *testing.T) {
	valid := Ring{Keys: []Key{{ID: "current", Key: strings.Repeat("ab", 32), NotBefore: 10, NotAfter: 100}}}
	for name, mutate := range map[string]func(*Ring){
		"empty": func(r *Ring) { r.Keys = nil },
		"duplicate ID": func(r *Ring) {
			r.Keys = append(r.Keys, Key{ID: "current", Key: strings.Repeat("cd", 32), NotAfter: 100})
		},
		"duplicate material": func(r *Ring) { r.Keys = append(r.Keys, Key{ID: "previous", Key: r.Keys[0].Key, NotAfter: 100}) },
		"invalid ID":         func(r *Ring) { r.Keys[0].ID = "a.b" },
		"uppercase key":      func(r *Ring) { r.Keys[0].Key = strings.ToUpper(r.Keys[0].Key) },
		"missing expiry":     func(r *Ring) { r.Keys[0].NotAfter = 0 },
		"unsafe timestamp":   func(r *Ring) { r.Keys[0].NotAfter = 9007199254740992 },
	} {
		t.Run(name, func(t *testing.T) {
			r := Ring{Keys: append([]Key(nil), valid.Keys...)}
			mutate(&r)
			raw, _ := json.Marshal(r)
			if _, err := Parse(raw); err == nil {
				t.Fatal("invalid ring accepted")
			}
		})
	}
	raw, _ := json.Marshal(valid)
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("public signing material accepted")
	}
}

func TestRingDigestBindsMaterialWindowsAndIgnoresOrder(t *testing.T) {
	r := Ring{Keys: []Key{{ID: "a", Key: strings.Repeat("ab", 32), NotBefore: 1, NotAfter: 100}, {ID: "b", Key: strings.Repeat("cd", 32), NotBefore: 2, NotAfter: 200}}}
	original := r.Digest()
	r.Keys[0], r.Keys[1] = r.Keys[1], r.Keys[0]
	if r.Digest() != original {
		t.Fatal("digest depends on ring order")
	}
	r.Keys[0].NotAfter++
	if r.Digest() == original {
		t.Fatal("expiry missing from digest")
	}
	r.Keys[0].NotAfter--
	r.Keys[0].Key = strings.Repeat("ef", 32)
	if r.Digest() == original {
		t.Fatal("material missing from digest")
	}
}
