package region

import (
	"strings"
	"testing"
	"time"
)

func TestPoolGrowthBindingIsImmutableIncludingLegacyAbsence(t *testing.T) {
	child, _, updated := protectedChildFixture()
	original := *child.Launch
	original.ExpiresAt = updated.Add(time.Minute)
	original.GrowthAuthority = PoolGrowthAuthority{SourceSHA256: strings.Repeat("c", 64), BindingSHA256: strings.Repeat("a", 64), ExpiresAt: original.ExpiresAt, BirthEpoch: 7}
	if err := original.validate(updated); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		name   string
		change func(*PoolWireRecord)
	}{
		{"replace original binding", func(w *PoolWireRecord) { w.GrowthAuthority.BindingSHA256 = strings.Repeat("b", 64) }},
		{"erase original binding", func(w *PoolWireRecord) { w.GrowthAuthority.BindingSHA256 = "" }},
		{"replace original source", func(w *PoolWireRecord) { w.GrowthAuthority.SourceSHA256 = strings.Repeat("b", 64) }},
		{"extend original source cap", func(w *PoolWireRecord) { w.GrowthAuthority.ExpiresAt = w.GrowthAuthority.ExpiresAt.Add(time.Minute) }},
		{"replace original birth epoch", func(w *PoolWireRecord) { w.GrowthAuthority.BirthEpoch++ }},
		{"extend original expiry", func(w *PoolWireRecord) { w.ExpiresAt = w.ExpiresAt.Add(time.Minute) }},
		{"erase original expiry", func(w *PoolWireRecord) { w.ExpiresAt = time.Time{} }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			next := original
			mutation.change(&next)
			if retainPoolWire(&original, &next) {
				t.Fatal("saved growth wire adopted successor mutation authority")
			}
		})
	}
	legacy := original
	legacy.GrowthAuthority, legacy.ExpiresAt = PoolGrowthAuthority{}, time.Time{}
	if retainPoolWire(&legacy, &original) {
		t.Fatal("legacy wire retroactively gained original binding and expiry")
	}
	bad := original
	bad.ExpiresAt = time.Time{}
	if err := bad.validate(updated); err == nil {
		t.Fatal("growth binding accepted without an original finite expiry")
	}
	bad = original
	bad.GrowthAuthority.BindingSHA256 = "not-a-digest"
	if err := bad.validate(updated); err == nil {
		t.Fatal("invalid growth binding accepted")
	}
}
