package bootstrapmaterial

import "testing"

type ObservabilityRegionForTest struct {
	Material, Directory string
	Record              InterRegionRecord
}

// ObservabilityLinkFixture reuses the issued regional material and reviewed link inputs across the package boundary.
func ObservabilityLinkFixture(t *testing.T) (ObservabilityRegionForTest, ObservabilityRegionForTest, *ParentLink) {
	t.Helper()
	gru, sfo, _ := linkedRegions(t)
	wire, reviewed := receipt(t, nil)
	link := &ParentLink{Record: gru.record, Receipt: Readback{wire, reviewed}, NetBird: netbirdReadback(t, nil),
		CredentialsFile: childCredentials(t, gru, "sfo")}
	return ObservabilityRegionForTest{gru.material, gru.directory, gru.record},
		ObservabilityRegionForTest{sfo.material, sfo.directory, sfo.record}, link
}

var CredentialsForTest = credentials
