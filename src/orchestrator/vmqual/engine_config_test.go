package vmqual

import (
	"path/filepath"
	"testing"
)

func TestTerraBaseDeclarationEnvironmentPath(t *testing.T) {
	t.Setenv("TS_VM_TERRABASE_DECLARATION_FILE", "tmp/member-declaration.json")
	c := DefaultConfig()
	if c.TerraBaseDeclarationFile != filepath.Join(repositoryRoot(), "tmp/member-declaration.json") {
		t.Fatal("declaration was not resolved against repository")
	}
	c.TerraBaseDeclarationFile = "../unsafe"
	if c.Validate() == nil {
		t.Fatal("relative engine declaration accepted")
	}
}
