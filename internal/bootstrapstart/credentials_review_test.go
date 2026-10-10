package bootstrapstart

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A controller whose signed material includes membership.creds must pass the
// live credential path check once its config names that file, and a
// configured but unsigned membership credential is refused.
func TestCredentialCheckerPinsTheOptionalMembershipCredential(t *testing.T) {
	check, expected := credentialPathFixture(t)
	path := filepath.Join(check.directory, "membership.creds")
	content := []byte("signed fixture membership.creds")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	expected["membership.creds"] = digest(content)
	if err := check.verifyInitialPaths(ManifestPins(expected), peerCredentialManifest); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("signed but unconfigured membership credential = %v", err)
	}
	embedded := *check.Config.Embedded
	embedded.MembershipCredentialsFile = path
	check.Config.Embedded = &embedded
	if err := check.verifyInitialPaths(ManifestPins(expected), peerCredentialManifest); err != nil {
		t.Fatalf("signed and configured membership credential: %v", err)
	}
	if err := check.verifyInventory(ManifestPins(expected)); err != nil {
		t.Fatal(err)
	}
	delete(expected, "membership.creds")
	if err := check.verifyInitialPaths(ManifestPins(expected), peerCredentialManifest); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("configured but unsigned membership credential = %v", err)
	}
}
