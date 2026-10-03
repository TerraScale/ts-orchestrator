package tier

import (
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// recorder stands in for a test so the helpers' skip and failure outcomes can
// be observed; both end the helper like runtime.Goexit would.
type recorder struct {
	testing.TB
	outcome, message string
}

type stopped struct{}

func (r *recorder) Helper() {}
func (r *recorder) Fatal(args ...any) {
	r.outcome, r.message = "fail", fmt.Sprint(args...)
	panic(stopped{})
}
func (r *recorder) Fatalf(format string, args ...any) {
	r.outcome, r.message = "fail", fmt.Sprintf(format, args...)
	panic(stopped{})
}
func (r *recorder) Skipf(format string, args ...any) {
	r.outcome, r.message = "skip", fmt.Sprintf(format, args...)
	panic(stopped{})
}

func observe(t *testing.T, call func(testing.TB) []string) (*recorder, []string) {
	t.Helper()
	r := &recorder{TB: t}
	var values []string
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				if _, ok := recovered.(stopped); !ok {
					panic(recovered)
				}
			}
		}()
		values = call(r)
		r.outcome = "run"
	}()
	return r, values
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
			t.Setenv(Env, tc.tier)
			t.Setenv("TS_TIER_TEST_A", tc.a)
			t.Setenv("TS_TIER_TEST_B", tc.b)
			r, values := observe(t, func(tb testing.TB) []string { return Qualification(tb, "TS_TIER_TEST_A", "TS_TIER_TEST_B") })
			if r.outcome != tc.outcome || !strings.Contains(r.message, tc.message) || !reflect.DeepEqual(values, tc.values) {
				t.Fatalf("outcome=%s message=%q values=%q", r.outcome, r.message, values)
			}
		})
	}
	t.Run("needs-a-variable", func(t *testing.T) {
		if r, _ := observe(t, func(tb testing.TB) []string { return Qualification(tb) }); r.outcome != "fail" {
			t.Fatalf("outcome=%s", r.outcome)
		}
	})
}

func TestUnavailable(t *testing.T) {
	for tier, outcome := range map[string]string{"": "skip", "pr": "skip", QualificationTier: "fail"} {
		t.Setenv(Env, tier)
		r, _ := observe(t, func(tb testing.TB) []string { Unavailable(tb, "needs %s", "a packet"); return nil })
		if r.outcome != outcome || !strings.HasSuffix(r.message, "needs a packet") {
			t.Fatalf("tier %q: outcome=%s message=%q", tier, r.outcome, r.message)
		}
	}
}

// TestIntegrationChild is run by TestIntegration in a child test binary.
func TestIntegrationChild(t *testing.T) {
	if os.Getenv("TS_TIER_INTEGRATION_CHILD") != "1" {
		t.Skip("child of TestIntegration")
	}
	Integration(t)
	t.Log("integration test body ran")
}

func TestIntegration(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		ran  bool
	}{{nil, true}, {[]string{"-test.short"}, false}} {
		cmd := exec.Command(executable, append([]string{"-test.run=^TestIntegrationChild$", "-test.v"}, tc.args...)...)
		cmd.Env = append(os.Environ(), "TS_TIER_INTEGRATION_CHILD=1", "GORACE=atexit_sleep_ms=0")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", tc.args, err, output)
		}
		if ran := strings.Contains(string(output), "integration test body ran"); ran != tc.ran {
			t.Fatalf("%v: body ran=%v\n%s", tc.args, ran, output)
		}
		if skipped := strings.Contains(string(output), "--- SKIP: TestIntegrationChild"); skipped == tc.ran {
			t.Fatalf("%v: skipped=%v\n%s", tc.args, skipped, output)
		}
	}
}
