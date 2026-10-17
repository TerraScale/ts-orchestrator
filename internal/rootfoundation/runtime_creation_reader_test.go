package rootfoundation

import "testing"

func TestProtectedRuntimeCreationRejectsZeroProof(t *testing.T) {
	if err := (VerifiedRuntimeCreation{}).Revalidate(t.Context()); err == nil {
		t.Fatal("unverified manager acquired protected original creation authority")
	}
}
