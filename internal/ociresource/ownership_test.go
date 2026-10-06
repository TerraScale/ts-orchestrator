package ociresource

import "testing"

func TestClaimedSeesAnyPartOfAnOwnershipClaim(t *testing.T) {
	key := Key{Region: "GRU", Kind: "lb-backends", Name: "public-terrabase"}
	for _, mode := range []TagMode{TagModeFreeform, TagModeDefined} {
		ours := Ownership{Mode: mode, Owner: "cell-gru"}
		if ours.Claimed(Tags{}) || ours.Claimed(Tags{Freeform: map[string]string{"CostCenter": "infra"}}) {
			t.Fatalf("%s: unclaimed tags read as claimed", mode)
		}
		if !ours.Claimed(ours.Stamp(key, 0, "")) || !ours.Claimed(Ownership{Mode: mode, Owner: "other"}.Stamp(key, 3, "d")) {
			t.Fatalf("%s: a full claim read as unclaimed", mode)
		}
		// Each marker alone is a claim, even without managed-by.
		stamped := ours.Stamp(key, 0, "")
		for name, value := range stamped.Freeform {
			if name == freeformGeneration || name == freeformSpecDigest {
				continue
			}
			if !ours.Claimed(Tags{Freeform: map[string]string{name: value}}) {
				t.Fatalf("missed the partial freeform claim %s", name)
			}
		}
		for namespace, values := range stamped.Defined {
			for name, value := range values {
				if name == definedGeneration || name == definedSpecDigest {
					continue
				}
				if !ours.Claimed(Tags{Defined: map[string]map[string]any{namespace: {name: value}}}) {
					t.Fatalf("missed the partial defined claim %s", name)
				}
			}
		}
	}
	// A freeform claim is not one in defined mode, and the reverse.
	freeform := Ownership{Mode: TagModeFreeform, Owner: "cell-gru"}
	defined := Ownership{Mode: TagModeDefined, Owner: "cell-gru"}
	if freeform.Claimed(defined.Stamp(key, 0, "")) || defined.Claimed(freeform.Stamp(key, 0, "")) {
		t.Fatal("a claim in the other tag mode read as claimed")
	}
}
