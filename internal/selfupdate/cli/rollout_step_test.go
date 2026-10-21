package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutexec"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// The watchdog is the node's root step agent: with the production default
// (no rollouts block) it applies the step the unit's process spooled and
// restarts the unit when the step owes a restart.
func TestWatchdogAppliesTheUnitsSpooledRolloutStep(t *testing.T) {
	controller, host := selfupdate.ControllerUnit, selfupdate.HostUnit
	for _, tc := range []struct {
		name, unit, node string
		// config returns the role config for the response key file and the
		// base64 public key.
		config  func(keyFile, public string) string
		applied bool
	}{
		{"production default", controller, "ctl-a", func(key, _ string) string {
			return `{"version":2,"nats":{"cell":"gru","instance":"ctl-a"},"controller":{"response_key_file":"` + key + `"}}`
		}, true},
		{"production host", host, "gru-1-db-1", func(_, public string) string {
			return `{"version":2,"nats":{"cell":"gru"},"host":{"node":"gru-1-db-1","controller_public_key":"` + public + `"}}`
		}, true},
		{"host on a controller's VM", host, "gru-1-ctl-1", func(_, public string) string {
			return `{"version":2,"nats":{"cell":"gru"},"host":{"node":"gru-1-ctl-1","controller_public_key":"` + public + `"}}`
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "root")
			owner := fmt.Sprint(os.Getuid())
			layout := selfupdate.Layout{Root: root, Owner: os.Getuid()}
			unit := tc.unit
			baked := filepath.Join(dir, "baked")
			if err := os.WriteFile(baked, []byte("baked build"), 0o755); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			var restarted []string
			invoke := func(args ...string) (string, error) {
				var output bytes.Buffer
				err := run(t.Context(), args, &output, func() time.Time { return now }, func(_ context.Context, unit string) error {
					restarted = append(restarted, unit)
					return nil
				})
				return output.String(), err
			}
			if _, err := invoke("prepare", "--root", root, "--owner", owner, "--unit", unit, "--baked-binary", baked); err != nil {
				t.Fatal(err)
			}
			previous, err := layout.Current()
			if err != nil {
				t.Fatal(err)
			}
			target := []byte("target build")
			sum := sha256.Sum256(target)
			digest := hex.EncodeToString(sum[:])
			if err := os.Mkdir(layout.ReleaseDir(digest), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(layout.BinaryPath(digest), target, 0o555); err != nil {
				t.Fatal(err)
			}
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			keyFile := filepath.Join(dir, "response.key")
			if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(dir, "controller.json")
			if unit == host {
				config = filepath.Join(dir, "host.json")
				// gru-1-ctl-1's host shares its VM with a controller.
				if tc.node == "gru-1-ctl-1" {
					if err := os.WriteFile(filepath.Join(dir, "controller.json"), []byte(`{}`), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			public := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
			if err := os.WriteFile(config, []byte(tc.config(keyFile, public)), 0o600); err != nil {
				t.Fatal(err)
			}
			spool := filepath.Join(dir, "spool")
			if err := os.Mkdir(spool, 0o700); err != nil {
				t.Fatal(err)
			}
			step, err := rolloutexec.SignStepCommand(rolloutexec.StepCommand{Schema: rolloutexec.StepSchema, Cell: "gru",
				RolloutID: "0000000000N710EPNTQEYZ67K1", Kind: rollout.KindController, Unit: tc.node,
				OperationID: rollout.OperationID("0000000000N710EPNTQEYZ67K1", tc.node, rollout.PhaseCanary, 0),
				Action:      rolloutexec.StepPrepare, Digest: digest, Replaces: previous, Epoch: 3, ProofWindowSeconds: 60},
				key, now, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(spool, "step.json"), step, 0o600); err != nil {
				t.Fatal(err)
			}
			previousSpool, previousHostSpool, previousBaked := rolloutSpoolDir, hostSpoolDir, bakedInputs
			rolloutSpoolDir, hostSpoolDir = spool, spool
			rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			genesis, err := trust.ParseKeyring(rootPublic)
			if err != nil {
				t.Fatal(err)
			}
			bakedInputs = func() (bootstrapstart.BakedInputs, error) {
				return bootstrapstart.BakedInputs{Genesis: genesis, Chain: trust.RootChain{Version: 1}, Identity: bootstrapstart.BakedIdentity{
					DeploymentID: "0000000000FBPQEED3YHZXX2AS", Environment: "canary", Cell: "GRU"}}, nil
			}
			if unit == controller {
				useAcceptedController(t, controllerAcceptedFixture(t, []byte("baked build")), genesis)
				receipt, delegation := signAcceptedSuccessor(t, target, now, rootPrivate, genesis)
				for name, wire := range map[string][]byte{"receipt.json": receipt, "delegation.json": delegation} {
					if err := os.WriteFile(filepath.Join(layout.ReleaseDir(digest), name), wire, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			t.Cleanup(func() { rolloutSpoolDir, hostSpoolDir, bakedInputs = previousSpool, previousHostSpool, previousBaked })

			if _, err := invoke("watchdog", "--root", root, "--owner", owner, "--unit", unit, "--config", config); err != nil {
				t.Fatal(err)
			}
			activation, pending, err := layout.Pending()
			if err != nil {
				t.Fatal(err)
			}
			data, replyErr := os.ReadFile(filepath.Join(root, rolloutexec.ReplyFile(unit)))
			if !tc.applied {
				if pending || len(restarted) != 0 || replyErr == nil {
					t.Fatalf("a step was applied: pending %v, restarts %v, reply %s", pending, restarted, data)
				}
				return
			}
			var reply rolloutexec.StepReply
			if replyErr != nil || json.Unmarshal(data, &reply) != nil || reply.Outcome != rolloutexec.OutcomeActivated {
				t.Fatalf("reply = %s %v", data, replyErr)
			}
			if !pending || activation.Target != digest || len(restarted) != 1 || restarted[0] != unit {
				t.Fatalf("activation %+v pending %v, restarts %v", activation, pending, restarted)
			}
			if owed, err := layout.RestartPending(unit); err != nil || owed {
				t.Fatalf("the watchdog did not serve the restart the step owed: %v %v", owed, err)
			}
		})
	}
}
