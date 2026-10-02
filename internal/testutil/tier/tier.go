// Package tier selects which test tier a Go test belongs to.
//
// T0 runs on every pull request with `go test -short`: unit tests and the
// single-process fencing, lease, trust and image-safety invariants. T1 runs
// on every push to develop and main without -short and adds the tests that
// call Integration: multi-process NATS labs and repeated offline image
// builds. T2 runs before an image is built, with TS_TEST_TIER=qualification,
// and adds the tests that call Qualification: real TerraBase members,
// Firecracker fixtures and cross-language packets supplied through the
// environment. Outside T2 those tests skip; inside it a missing fixture is a
// failure, so a qualification gate can never pass by skipping.
package tier

import (
	"os"
	"strings"
	"testing"
)

// Env names the test tier of the current run.
const Env = "TS_TEST_TIER"

// QualificationTier is the Env value of a pre-deploy qualification run.
const QualificationTier = "qualification"

// Qualifying reports whether this run is a T2 qualification run.
func Qualifying() bool { return os.Getenv(Env) == QualificationTier }

// Integration marks a T1 test: a multi-process lab or a slow end-to-end
// contract whose invariants T0 already covers with a single-process test.
// It skips under go test -short.
func Integration(t testing.TB) {
	t.Helper()
	if testing.Short() {
		t.Skip("integration tier: runs without -short on pushes to develop and main")
	}
}

// Qualification marks a T2 test that needs real infrastructure named by
// environment variables, and returns their values in order. When any of them
// is unset or empty the test skips, except in a qualification run, where it
// fails: the fixture the gate promised is missing.
func Qualification(t testing.TB, envs ...string) []string {
	t.Helper()
	if len(envs) == 0 {
		t.Fatal("tier.Qualification needs the environment variables that supply its fixture")
	}
	values := make([]string, len(envs))
	var missing []string
	for i, name := range envs {
		values[i] = os.Getenv(name)
		if values[i] == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		Unavailable(t, "qualification fixture not supplied: set %s", strings.Join(missing, ", "))
	}
	return values
}

// Unavailable reports that a T2 fixture is missing for a reason the caller
// determined itself, such as an opt-in that needs one of several variables.
// It skips the test, or fails it in a qualification run.
func Unavailable(t testing.TB, format string, args ...any) {
	t.Helper()
	if Qualifying() {
		t.Fatalf(Env+"="+QualificationTier+": "+format, args...)
	}
	t.Skipf(format, args...)
}
