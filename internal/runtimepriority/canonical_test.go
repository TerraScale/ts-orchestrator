package runtimepriority

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestCanonicalRetainsUnicodeEvidenceHashContract(t *testing.T) {
	value, _, err := LoadJSON("testdata/canonical-unicode.json", 4096)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/canonical-unicode.ascii.json")
	if err != nil {
		t.Fatal(err)
	}
	want = bytes.TrimSuffix(want, []byte{'\n'})
	got := Canonical(value)
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical Unicode encoding changed:\n got %s\nwant %s", got, want)
	}
	digest, err := os.ReadFile("testdata/canonical-unicode.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if Hash(got) != strings.TrimSpace(string(digest)) {
		t.Fatalf("Unicode evidence hash changed: %s", Hash(got))
	}
}
