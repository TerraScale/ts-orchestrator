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
		"engine.proto": "356905038a8fd071bb9a54e2f8676f1618e4053845142fe4ab18b3e1a5264767",
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
