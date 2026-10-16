package tier

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func tierChild(t *testing.T, mode string, env []string, args ...string) (string, int) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, append([]string{"-test.run=^TestIntegrationChild$", "-test.v"}, args...)...)
	cmd.Env = append(os.Environ(), Env+"=", "TS_TIER_TEST_A=", "TS_TIER_TEST_B=",
		"TS_TIER_INTEGRATION_CHILD=1", "TS_TIER_CHILD_MODE="+mode, "GORACE=atexit_sleep_ms=0")
	cmd.Env = append(cmd.Env, env...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil || cmd.ProcessState == nil {
		t.Fatalf("tier child %s: %v, context=%v\n%s", mode, err, ctx.Err(), output)
	}
	return string(output), cmd.ProcessState.ExitCode()
}

func checkTierOutcome(t *testing.T, output string, code int, outcome, message string) {
	t.Helper()
	status, wantCode := "PASS", 0
	switch outcome {
	case "skip":
		status = "SKIP"
	case "fail":
		status, wantCode = "FAIL", 1
	}
	if code != wantCode || !strings.Contains(output, "--- "+status+": TestIntegrationChild") || !strings.Contains(output, message) {
		t.Fatalf("want %s (exit %d) containing %q; exit %d:\n%s", status, wantCode, message, code, output)
	}
	if outcome == "fail" && strings.Contains(output, "--- SKIP:") {
		t.Fatalf("required qualification skipped instead of failing:\n%s", output)
	}
}

func TestQualification(t *testing.T) {
	for _, tc := range []struct {
		name, tier, a, b string
		outcome, message string
		values           []string
	}{
		{"supplied", "", "/fixture/a", "/fixture/b", "run", "", []string{"/fixture/a", "/fixture/b"}},
		{"supplied-qualifying", QualificationTier, "/fixture/a", "/fixture/b", "run", "", []string{"/fixture/a", "/fixture/b"}},
		{"missing-skips", "", "", "", "skip", "qualification fixture not supplied: set TS_TIER_TEST_A, TS_TIER_TEST_B", nil},
		{"partial-skips", "full", "/fixture/a", "", "skip", "set TS_TIER_TEST_B", nil},
		{"missing-fails-qualifying", QualificationTier, "/fixture/a", "", "fail", "TS_TEST_TIER=qualification: qualification fixture not supplied: set TS_TIER_TEST_B", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, code := tierChild(t, "qualification", []string{Env + "=" + tc.tier, "TS_TIER_TEST_A=" + tc.a, "TS_TIER_TEST_B=" + tc.b})
			checkTierOutcome(t, output, code, tc.outcome, tc.message)
			if tc.outcome == "run" && !strings.Contains(output, fmt.Sprintf("fixture-values=%q", tc.values)) {
				t.Fatalf("returned fixture values or order changed:\n%s", output)
			}
			if tc.outcome != "run" && strings.Contains(output, "fixture-values=") {
				t.Fatalf("unavailable fixture continued into the test body:\n%s", output)
			}
		})
	}
	t.Run("needs-a-variable", func(t *testing.T) {
		output, code := tierChild(t, "no-variables", nil)
		checkTierOutcome(t, output, code, "fail", "tier.Qualification needs the environment variables that supply its fixture")
	})
}

func TestUnavailable(t *testing.T) {
	for tier, outcome := range map[string]string{"": "skip", "pr": "skip", QualificationTier: "fail"} {
		output, code := tierChild(t, "unavailable", []string{Env + "=" + tier})
		checkTierOutcome(t, output, code, outcome, "needs a packet\n")
	}
}

// TestIntegrationChild is run only in bounded child test processes.
func TestIntegrationChild(t *testing.T) {
	if os.Getenv("TS_TIER_INTEGRATION_CHILD") != "1" {
		t.Skip("child of the tier process scenarios")
	}
	switch os.Getenv("TS_TIER_CHILD_MODE") {
	case "qualification":
		values := Qualification(t, "TS_TIER_TEST_A", "TS_TIER_TEST_B")
		fmt.Printf("fixture-values=%q\n", values)
	case "no-variables":
		Qualification(t)
	case "unavailable":
		Unavailable(t, "needs %s", "a packet")
	case "integration":
		Integration(t)
		t.Log("integration test body ran")
	default:
		t.Fatal("unknown child scenario")
	}
}

func TestIntegration(t *testing.T) {
	for _, tc := range []struct {
		args []string
		ran  bool
	}{{nil, true}, {[]string{"-test.short"}, false}} {
		output, code := tierChild(t, "integration", nil, tc.args...)
		outcome := "skip"
		if tc.ran {
			outcome = "run"
		}
		checkTierOutcome(t, output, code, outcome, "")
		if ran := strings.Contains(output, "integration test body ran"); ran != tc.ran {
			t.Fatalf("%v: body ran=%v\n%s", tc.args, ran, output)
		}
	}
}
