package tbep

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
)

// These are the exact complete producer files, including the imported family.
// A contract update must explicitly change both the provenance and these pins.
func TestPinnedContracts(t *testing.T) {
	for name, want := range map[string]string{
		"engine.proto": "a122c6de9446a0563db1f7cbe8027db408a152102c78e1605f13e7fa0fb784e4",
		"family.proto": "cdae480893d6aa1ff8d88af5a352d8e9ab1f59a60fe13d93ca6da387a7a109ec",
	} {
		data, err := os.ReadFile("contracts/terrabase/v1/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
			t.Errorf("%s pin changed: %s", name, got)
		}
	}
}
