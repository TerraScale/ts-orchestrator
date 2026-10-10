package selfupdate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIdentityRekeyBaselinePublishesPairAndRefusesUnresolvedTransitions(t *testing.T) {
	for _, fault := range []string{"none", "activation", "restore", "candidate", "guard", "crash"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			old, err := Seed(f.layout, f.baked)
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("root checkpoint approved compatible CI binary")
			receipt, delegation := f.signed(data)
			candidate := filepath.Join(t.TempDir(), "candidate")
			if err := os.WriteFile(candidate, data, 0o755); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "activation":
				next := f.stage([]byte("pending old deployment binary"))
				if _, err := Activate(f.layout, next, ControllerUnit, f.now, time.Minute); err != nil {
					t.Fatal(err)
				}
				old = next
			case "restore":
				if err := os.WriteFile(f.layout.restoreIntentPath(ControllerUnit), []byte("retained unresolved restore"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "candidate":
				if err := os.WriteFile(candidate, []byte("altered candidate"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			checks := 0
			check := func(string) error {
				checks++
				if fault == "guard" || fault == "crash" && checks == 4 {
					return errors.New("stopped service/proof check refused")
				}
				return nil
			}
			err = InstallIdentityRekeyBaseline(f.layout, candidate, receipt, delegation, f.policy(), f.now, check)
			if fault == "none" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatalf("%s accepted", fault)
			}
			current, readErr := f.layout.Current()
			if readErr != nil {
				t.Fatal(readErr)
			}
			good, readErr := f.layout.KnownGood()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if fault == "none" {
				if current != digestOf(data) || good != current {
					t.Fatal("approved baseline was not installed into both links")
				}
			} else if current != old || fault != "crash" && good != "" {
				t.Fatal("refusal changed a selection")
			}
			if fault == "crash" {
				if good != digestOf(data) {
					t.Fatal("crash did not retain the verified known-good publication")
				}
				if err := InstallIdentityRekeyBaseline(f.layout, candidate, receipt, delegation, f.policy(), f.now, func(string) error { return nil }); err != nil {
					t.Fatal(err)
				}
				if current, _ := f.layout.Current(); current != good {
					t.Fatal("retry did not finish both verified links")
				}
			}
			if fault == "activation" {
				if _, pending, err := f.layout.Pending(); err != nil || !pending {
					t.Fatal("refusal removed the old activation")
				}
			}
			if fault == "restore" {
				if wire, err := os.ReadFile(f.layout.restoreIntentPath(ControllerUnit)); err != nil || string(wire) != "retained unresolved restore" {
					t.Fatal("refusal removed the old restore")
				}
			}
		})
	}
}
