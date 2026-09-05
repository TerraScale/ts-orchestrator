package main

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

func TestRunRejectsUnknownCommandBeforeRuntimeIdentityResolution(t *testing.T) {
	unsetTestEnvironment(t, "TS_VM_JAILER_UID", "TS_VM_JAILER_GID", "SUDO_UID", "SUDO_GID")
	err := run(context.Background(), []string{"unknown"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || err.Error() != "unknown command" {
		t.Fatalf("run error = %v", err)
	}
}

func TestRealComponentsRequiresNonRootRuntimeIdentityFirst(t *testing.T) {
	unsetTestEnvironment(t, "TS_VM_JAILER_UID", "TS_VM_JAILER_GID", "SUDO_UID", "SUDO_GID")
	config := vmqual.DefaultConfig()
	_, _, err := realComponents(context.Background(), config, false, false)
	if err == nil || !strings.Contains(err.Error(), "nonzero jailer UID/GID") {
		t.Fatalf("realComponents error = %v", err)
	}
}

func unsetTestEnvironment(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		value, set := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
		name, value, set := name, value, set
		t.Cleanup(func() {
			if set {
				_ = os.Setenv(name, value)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
}

func TestQualificationProfilesPredeclareFourthRegionOnlyForSuite(t *testing.T) {
	for _, test := range []struct {
		name            string
		full, fourth    bool
		regions, guests int
	}{
		{"smoke", false, false, 1, 1}, {"stack", true, false, 3, 6}, {"test", true, true, 4, 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := qualificationNetworkConfig(test.full, test.fourth)
			guests := 0
			for _, region := range config.Regions {
				guests += len(region.Guests)
			}
			if len(config.Regions) != test.regions || guests != test.guests {
				t.Fatalf("network topology: %+v", config.Regions)
			}
			if test.fourth {
				region := config.Regions[3]
				if region.Code != vmqual.FourthRegion || region.Guests[0].ID != "iad-member-1" || region.Guests[1].ID != "iad-member-2" {
					t.Fatalf("fourth-region slots: %+v", region)
				}
				if !reflect.DeepEqual(config.Regions[:3], qualificationNetworkConfig(true, false).Regions) {
					t.Fatal("declaring IAD moved launch network slots")
				}
			}
		})
	}
}
