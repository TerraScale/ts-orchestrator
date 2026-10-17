package imagequalification

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/qualification"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/host"
)

func TestRootCredentialEvidenceCannotPromoteMissingOrDeletedImage(t *testing.T) {
	f := fixture(t)
	for _, test := range []struct {
		name, purpose string
		deleted       bool
	}{
		{name: "generic approval"},
		{name: "missing exact image", purpose: qualification.RootCredentialBoundaryPurpose},
		{name: "destroyed tested image", purpose: qualification.RootCredentialBoundaryPurpose, deleted: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := f.prepared
			p.approval.Candidate.Role = release.FoundationWriterRole
			p.approval.Purpose = test.purpose
			directory := t.TempDir()
			j := journal{ImageDeleted: test.deleted}
			if test.deleted {
				j.ImageID = "ocid1.image.oc1.sa-saopaulo-1.destroyed"
			}
			proof, err := retainRootCredentialEvidence(p, host.Report{}, release.RootCredentialBoundaryEvidence{}, j, nil, nil, directory, f.now)
			if err == nil || proof.Gate != "" {
				t.Fatal("incomplete gate promoted")
			}
			if _, err := os.Stat(filepath.Join(directory, "objects")); !os.IsNotExist(err) {
				t.Fatal("rejected gate retained an evidence object")
			}
			if _, err := os.Stat(filepath.Join(directory, "production.unsigned.json")); !os.IsNotExist(err) {
				t.Fatal("isolated gate emitted production qualification")
			}
		})
	}
}
