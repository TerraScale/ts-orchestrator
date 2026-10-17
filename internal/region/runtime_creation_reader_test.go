package region

import "testing"

func TestOriginalRuntimeSourceCannotBeProjectedFromPayload(t *testing.T) {
	proof := VerifiedRuntimeCreationSource{}
	if err := proof.Revalidate(t.Context()); err == nil {
		t.Fatal("zero protected source proof authorized a runtime")
	}
	proof.genesis.ClusterID = "actual"
	creation := proof.Creation()
	creation.Genesis.ClusterID = "caller-replacement"
	if proof.Genesis().ClusterID != "actual" {
		t.Fatal("public source payload changed retained proof")
	}
}
