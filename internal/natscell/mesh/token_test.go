package mesh

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClientTokenSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	first, err := clientToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := clientToken(dir)
	if err != nil || again != first {
		t.Fatalf("restart changed the token: %q -> %q (%v)", first, again, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client.token"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	replaced, err := clientToken(dir)
	if err != nil || replaced == "garbage" || len(replaced) != 64 {
		t.Fatalf("invalid token kept: %q (%v)", replaced, err)
	}
}
