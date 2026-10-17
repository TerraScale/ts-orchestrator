package qualification

import (
	"strings"
	"testing"
	"time"
)

func TestOriginalDispositionAndExactReadIAM(t *testing.T) {
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	retain, transfer, cleanup := now.Add(50*time.Minute), now.Add(45*time.Minute), now.Add(time.Hour)
	if err := ValidateDisposition(RootCredentialBoundaryPurpose, RetainTestedImage, ExactHostReaders, retain, transfer, cleanup); err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []string{"", "native-runtime-ha"} {
		if ValidateDisposition(purpose, RetainTestedImage, ExactHostReaders, retain, transfer, cleanup) == nil {
			t.Fatal("unrelated purpose granted retention")
		}
	}
	if ValidateDisposition(RootCredentialBoundaryPurpose, "", ExactHostReaders, retain, transfer, cleanup) == nil || ValidateDisposition(RootCredentialBoundaryPurpose, RetainTestedImage, ExactHostReaders, retain, cleanup, cleanup) == nil || ValidateDisposition(RootCredentialBoundaryPurpose, RetainTestedImage, ExactHostReaders, retain, transfer, retain) == nil {
		t.Fatal("missing disposition, expanded transfer or absent cleanup grace accepted")
	}
	ids := []string{"ocid1.instance.oc1.region.a", "ocid1.instance.oc1.region.b", "ocid1.instance.oc1.region.c", "ocid1.instance.oc1.region.d"}
	if ReaderMatchingRule(ids) == "" || ReaderMatchingRule(append(ids[:3:3], ids[0])) != "" {
		t.Fatal("exact instance group uniqueness changed")
	}
	for _, statement := range ReaderStatements("ocid1.dynamicgroup.oc1..test", "ocid1.compartment.oc1..test", retain) {
		for _, forbidden := range []string{"manage ", "usage-report", "RequestSummarizedUsages", "ListInstances", "ListVolumes", "SearchResources", "PutObject", "Create", "Update", "Delete", "vault"} {
			if strings.Contains(statement, forbidden) {
				t.Fatalf("unneeded read scope %q", statement)
			}
		}
		if !strings.Contains(statement, retain.Format(time.RFC3339)) {
			t.Fatal("read IAM lost finite expiration")
		}
	}
}
