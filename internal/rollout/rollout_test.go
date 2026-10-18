package rollout

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func declaration(format, formatMin, formatMax, replication, replicationMin, replicationMax uint64) CompatibilityDeclaration {
	return CompatibilityDeclaration{Schema: CompatibilitySchema,
		PersistentFormat: VersionedCapability{Version: format, Accepts: VersionRange{Min: formatMin, Max: formatMax}},
		Replication:      VersionedCapability{Version: replication, Accepts: VersionRange{Min: replicationMin, Max: replicationMax}},
		ClientData:       VersionedCapability{Version: 1, Accepts: VersionRange{Min: 1, Max: 1}}}
}

func TestAssessDerivesEveryStatementFromBothReleases(t *testing.T) {
	old := declaration(2, 1, 2, 4, 3, 4)
	for _, test := range []struct {
		name      string
		candidate CompatibilityDeclaration
		want      CompatibilityVerdict
	}{
		{"same", old, CompatibilityVerdict{true, true, true, true}},
		{"rollback-safe reader bump", declaration(2, 1, 3, 4, 4, 5),
			CompatibilityVerdict{true, true, true, true}},
		{"old cannot read candidate format", declaration(3, 2, 3, 4, 4, 5),
			CompatibilityVerdict{true, true, true, false}},
		{"narrower accepted formats", declaration(2, 2, 2, 4, 3, 4),
			CompatibilityVerdict{true, true, true, true}},
		{"candidate drops old format", declaration(3, 3, 3, 4, 3, 4),
			CompatibilityVerdict{true, true, false, false}},
		{"replication break", declaration(2, 1, 2, 6, 6, 6),
			CompatibilityVerdict{false, true, true, true}},
	} {
		verdict, err := Assess(old, test.candidate)
		if err != nil || verdict != test.want {
			t.Fatalf("%s: verdict %+v err %v, want %+v", test.name, verdict, err, test.want)
		}
		if _, err := RequireCompatible(old, test.candidate); (err == nil) != test.want.Compatible() ||
			err != nil && Classify(err) != ClassTerminal {
			t.Fatalf("%s: RequireCompatible = %v", test.name, err)
		}
	}
	clientBreak := old
	clientBreak.ClientData = VersionedCapability{Version: 2, Accepts: VersionRange{Min: 2, Max: 2}}
	if verdict, _ := Assess(old, clientBreak); verdict.ClientData || verdict.Compatible() {
		t.Fatalf("client data break was certified: %+v", verdict)
	}
}

func TestAssessFailsClosedOnMissingOrMalformedDeclarations(t *testing.T) {
	good := declaration(1, 1, 1, 1, 1, 1)
	for name, bad := range map[string]CompatibilityDeclaration{
		"empty":        {},
		"wrong schema": func() CompatibilityDeclaration { d := good; d.Schema = "v0"; return d }(),
		"zero version": func() CompatibilityDeclaration { d := good; d.Replication.Version = 0; return d }(),
		"inverted range": func() CompatibilityDeclaration {
			d := good
			d.PersistentFormat.Accepts = VersionRange{Min: 2, Max: 1}
			return d
		}(),
		"self unsupported": func() CompatibilityDeclaration { d := good; d.ClientData.Version = 9; return d }(),
	} {
		if _, err := Assess(good, bad); err == nil {
			t.Fatalf("%s candidate was assessed", name)
		}
		if _, err := Assess(bad, good); err == nil {
			t.Fatalf("%s predecessor was assessed", name)
		}
		if _, err := RequireCompatible(good, bad); Classify(err) != ClassTerminal {
			t.Fatalf("%s: malformed declaration is not terminal: %v", name, err)
		}
	}
}

func TestClassifyDefaultsToTerminal(t *testing.T) {
	base := errors.New("boom")
	if Classify(base) != ClassTerminal || IsTransient(nil) {
		t.Fatal("unclassified error is not terminal")
	}
	if !IsTransient(Transient(base)) || !IsTransient(fmt.Errorf("wrapped: %w", Transient(base))) {
		t.Fatal("transient mark lost through wrapping")
	}
	if IsTransient(Terminal(Transient(base))) {
		t.Fatal("outer terminal mark did not win")
	}
	if !IsTransient(fmt.Errorf("wait: %w", context.DeadlineExceeded)) {
		t.Fatal("deadline is not transient")
	}
	if Transient(nil) != nil || Terminal(nil) != nil {
		t.Fatal("nil was classified into an error")
	}
	if !errors.Is(Transient(base), base) || Transient(base).Error() != "boom" {
		t.Fatal("classification changed the error")
	}
}

func TestBackoffIsBoundedAndCapped(t *testing.T) {
	backoff := Backoff{Initial: time.Second, Max: 5 * time.Second, Attempts: 5}
	var delays []time.Duration
	for attempt := 1; ; attempt++ {
		delay, ok := backoff.Delay(attempt)
		if !ok {
			break
		}
		delays = append(delays, delay)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}
	if fmt.Sprint(delays) != fmt.Sprint(want) {
		t.Fatalf("delays = %v, want %v", delays, want)
	}
	if _, ok := (Backoff{}).Delay(1); ok {
		t.Fatal("zero backoff allowed a retry")
	}
	// Uncapped growth saturates instead of overflowing into a negative
	// delay that would collapse the schedule into immediate retries.
	uncapped := Backoff{Initial: time.Nanosecond, Attempts: 200}
	previous := time.Duration(0)
	for attempt := 1; attempt <= 200; attempt++ {
		delay, ok := uncapped.Delay(attempt)
		if !ok || delay < previous || delay <= 0 {
			t.Fatalf("attempt %d delay = %v (previous %v, ok %t)", attempt, delay, previous, ok)
		}
		previous = delay
	}
	if previous != math.MaxInt64 {
		t.Fatalf("uncapped delay saturated at %v", previous)
	}
}

func TestSoakTreatsUnknownProcessAndReportGapsAsUnknown(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	digest := strings.Repeat("c", 64)
	sample := func(offset time.Duration, pid int) SoakSample {
		return SoakSample{At: start.Add(offset), ArtifactDigest: digest, OperationID: "0000000000VWA5N990CSNH40S5",
			Phase: "canary-serving", Serving: true, ProcessPID: pid}
	}
	gap := func(offset time.Duration) SoakSample {
		s := sample(offset, 0)
		s.Gap = true
		return s
	}
	newSoak := func() *Soak { return &Soak{Window: time.Minute, Digest: digest, Promoted: "canary-serving"} }

	// A first sample without a PID does not disable restart detection.
	soak := newSoak()
	for _, s := range []SoakSample{sample(0, 0), sample(10*time.Second, 77)} {
		if _, err := soak.Observe(s); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := soak.Observe(sample(20*time.Second, 78)); !errors.Is(err, ErrSoakFailed) || Classify(err) != ClassTerminal {
		t.Fatalf("restart after a PID-less first sample = %v", err)
	}

	// A transient PID-less sample or report gap is not a restart, and the
	// window only completes on a reported sample.
	soak = newSoak()
	for _, s := range []SoakSample{sample(0, 77), sample(20*time.Second, 0), gap(40 * time.Second), gap(time.Minute)} {
		if done, err := soak.Observe(s); done || err != nil {
			t.Fatalf("sample at %s: %t %v", s.At.Sub(start), done, err)
		}
	}
	if done, err := soak.Observe(sample(70*time.Second, 77)); !done || err != nil {
		t.Fatalf("soak after a gap = %t %v", done, err)
	}

	// A gap does not hide the controller-owned fields.
	soak = newSoak()
	if _, err := soak.Observe(sample(0, 77)); err != nil {
		t.Fatal(err)
	}
	held := gap(10 * time.Second)
	held.Phase = "held"
	if _, err := soak.Observe(held); !errors.Is(err, ErrSoakFailed) {
		t.Fatalf("held seat during a gap = %v", err)
	}

	// A gap longer than the window is transient, not a known-bad verdict.
	soak = newSoak()
	for _, s := range []SoakSample{sample(0, 77), gap(30 * time.Second)} {
		if _, err := soak.Observe(s); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := soak.Observe(gap(2 * time.Minute)); err == nil || errors.Is(err, ErrSoakFailed) || !IsTransient(err) {
		t.Fatalf("long report gap = %v, want a transient error", err)
	}
}

func TestSoakRequiresAStableServingProcessForTheWholeWindow(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	healthy := func(offset time.Duration, pid int) SoakSample {
		return SoakSample{At: start.Add(offset), ArtifactDigest: strings.Repeat("c", 64), OperationID: "0000000000VWA5N990CSNH40S5",
			Phase: "canary-serving", Serving: true, ProcessPID: pid}
	}
	soak := &Soak{Window: time.Minute, Digest: strings.Repeat("c", 64), Promoted: "canary-serving"}
	for _, offset := range []time.Duration{0, 20 * time.Second, 40 * time.Second} {
		if done, err := soak.Observe(healthy(offset, 77)); done || err != nil {
			t.Fatalf("soak ended early at %s: %t %v", offset, done, err)
		}
	}
	if remaining := soak.Remaining(start.Add(40 * time.Second)); remaining != 20*time.Second {
		t.Fatalf("remaining = %s", remaining)
	}
	if done, err := soak.Observe(healthy(time.Minute, 77)); !done || err != nil {
		t.Fatalf("healthy soak did not pass: %t %v", done, err)
	}

	for name, sample := range map[string]SoakSample{
		"restart":     healthy(30*time.Second, 78),
		"not serving": func() SoakSample { s := healthy(30*time.Second, 77); s.Serving = false; return s }(),
		"held":        func() SoakSample { s := healthy(30*time.Second, 77); s.Phase = "held"; return s }(),
		"replaced": func() SoakSample {
			s := healthy(30*time.Second, 77)
			s.ArtifactDigest = strings.Repeat("d", 64)
			return s
		}(),
		"new op": func() SoakSample {
			s := healthy(30*time.Second, 77)
			s.OperationID = "0000000000XAEJFGHY9DQZTT6W"
			return s
		}(),
	} {
		soak := &Soak{Window: time.Minute, Digest: strings.Repeat("c", 64), Promoted: "canary-serving"}
		if _, err := soak.Observe(healthy(0, 77)); err != nil {
			t.Fatal(err)
		}
		if _, err := soak.Observe(sample); !errors.Is(err, ErrSoakFailed) || Classify(err) != ClassTerminal {
			t.Fatalf("%s did not fail the soak terminally: %v", name, err)
		}
	}
	disabled := &Soak{Digest: strings.Repeat("c", 64), Promoted: "canary-serving"}
	if done, err := disabled.Observe(healthy(0, 1)); !done || err != nil {
		t.Fatalf("zero soak window did not pass on a healthy sample: %t %v", done, err)
	}
	gap := healthy(0, 0)
	gap.Gap = true
	disabled = &Soak{Digest: strings.Repeat("c", 64), Promoted: "canary-serving"}
	if done, err := disabled.Observe(gap); !done || err != nil {
		t.Fatalf("zero soak window waited for a host report: %t %v", done, err)
	}
}

