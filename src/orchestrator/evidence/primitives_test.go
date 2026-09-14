package evidence

import "testing"

func TestEvidenceIdentifierBoundaries(t *testing.T) {
	valid, ok := EvidenceTreeIdTryCreate("tree/main", 9)
	if !ok || !valid.IsValid() {
		t.Fatal("expected a bounded identifier to be accepted")
	}
	for _, value := range []string{"", "tree main", "tree@main"} {
		if _, ok := EvidenceTreeIdTryCreate(value, 32); ok {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
	if _, ok := EvidenceTreeIdTryCreate("tree/main", 8); ok {
		t.Fatal("expected an identifier over the limit to be rejected")
	}
}

func TestEvidenceDigestAndSignatureCopies(t *testing.T) {
	source := make([]byte, 32)
	source[0] = 7
	digest, ok := EvidenceSha256TryCreate(source)
	if !ok {
		t.Fatal("expected a 32-byte digest")
	}
	source[0] = 9
	copyOfDigest := digest.CopyBytes()
	if copyOfDigest[0] != 7 {
		t.Fatal("digest retained a caller-owned backing array")
	}
	copyOfDigest[0] = 11
	if digest.CopyBytes()[0] != 7 {
		t.Fatal("digest exposed mutable internal state")
	}

	signature := NewEvidenceOpaqueSignature([]byte{1, 2, 3}, 3)
	if !signature.IsValid() || len(signature.CopyBytes()) != 3 {
		t.Fatal("expected a valid bounded signature")
	}
	if NewEvidenceOpaqueSignature([]byte{1, 2, 3, 4}, 3).IsValid() {
		t.Fatal("expected an oversized signature to be rejected")
	}
}

func TestEvidenceCollectionsSnapshotCapsAndValidates(t *testing.T) {
	snapshot, ok := CollectionsSnapshot([]string{"a", "b", "c"}, 2, true)
	if !ok || len(snapshot) != 2 {
		t.Fatalf("unexpected bounded snapshot: %#v, %v", snapshot, ok)
	}
	snapshot[0] = "changed"
	original := []string{"a", "b", "c"}
	if original[0] != "a" {
		t.Fatal("test setup unexpectedly changed")
	}
	if _, ok := CollectionsSnapshot([]string{}, 2, true); ok {
		t.Fatal("expected an empty required collection to be rejected")
	}
	if _, ok := CollectionsSnapshot([]string{"a"}, 0, false); ok {
		t.Fatal("expected a non-positive cap to be rejected")
	}
}

func TestEvidenceEnumValidation(t *testing.T) {
	if !LaneIsDefined(EvidenceLaneFull) || LaneIsDefined(EvidenceLane(99)) {
		t.Fatal("unexpected lane validation")
	}
	if !DomainIsDefined(EvidenceDomainRuntime) || DomainIsDefined(EvidenceDomain(-1)) {
		t.Fatal("unexpected domain validation")
	}
	if !GateTargetIsDefined(EvidenceGateTargetDependencyConformance) ||
		GateTargetIsDefined(EvidenceGateTarget(99)) {
		t.Fatal("unexpected gate-target validation")
	}
}
