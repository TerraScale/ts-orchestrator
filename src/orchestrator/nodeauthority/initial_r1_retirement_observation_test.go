package nodeauthority

import "testing"

func TestInitialR1RetirementObservationIsExactAndImmutable(t *testing.T) {
	f := newInitialR1Fixture(t)
	if err := f.admit(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.guard.Retirement(t.Context()); err == nil {
		t.Fatal("unretired source returned cut authority")
	}
	command := f.command(t)
	if err := f.retire(t.Context(), command, nil); err != nil {
		t.Fatal(err)
	}
	first, err := f.guard.Retirement(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if first.CommandID != "retire-one" || first.PreviousManifestSHA256 != f.identity.ManifestSHA256 || first.ReplacementManifestSHA256 != initialR1Replacement() || first.LeaseID != command.LeaseID {
		t.Fatalf("retirement differs: %+v", first)
	}
	first.CommandID = "modified"
	again, err := f.guard.Retirement(t.Context())
	if err != nil || again.CommandID != "retire-one" {
		t.Fatalf("caller changed durable retirement: %+v %v", again, err)
	}
}
