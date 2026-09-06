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
		"engine.proto": "2ec657c36925ffdf9944bcb60d4bbd65b283bbf5a31f2e3ab5c85eaa7b5e0e16",
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
