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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rolloutexec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// The controller's watchdog is the node's root step agent: with the
// production default (no rollouts block) it applies the step the controller
// spooled and restarts the unit the step owes a restart; a lab controller,
// or one whose config turns the executor off, never applies one.
func TestWatchdogAppliesTheControllersSpooledRolloutStep(t *testing.T) {
	for _, tc := range []struct {
		name, nats, rollouts string
		applied              bool
	}{
		{"production default", `"cell":"gru","instance":"ctl-a"`, "", true},
		{"explicit executor", `"cell":"gru","instance":"ctl-a"`, `,"rollouts":{"enabled":true,"executor":true}`, true},
		{"executor off", `"cell":"gru","instance":"ctl-a"`, `,"rollouts":{"enabled":true}`, false},
		{"lab", `"cell":"gru","instance":"ctl-a","lab":true`, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "root")
			owner := fmt.Sprint(os.Getuid())
			layout := selfupdate.Layout{Root: root, Owner: os.Getuid()}
			unit := selfupdate.ControllerUnit
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
			if err := os.WriteFile(config, []byte(`{"nats":{`+tc.nats+`},"controller":{"response_key_file":"`+keyFile+`"`+
				tc.rollouts+`}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			spool := filepath.Join(dir, "spool")
			if err := os.Mkdir(spool, 0o700); err != nil {
				t.Fatal(err)
			}
			step, err := rolloutexec.SignStepCommand(rolloutexec.StepCommand{Schema: rolloutexec.StepSchema, Cell: "gru",
				RolloutID: "release-g1-controllers", Kind: rollout.KindController, Unit: "ctl-a",
				OperationID: rollout.OperationID("release-g1-controllers", "ctl-a", rollout.PhaseCanary, 0),
				Action:      rolloutexec.StepPrepare, Digest: digest, Replaces: previous, Epoch: 3, ProofWindowSeconds: 60},
				key, now, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(spool, "step.json"), step, 0o600); err != nil {
				t.Fatal(err)
			}
			previousSpool, previousBaked := rolloutSpoolDir, bakedInputs
			rolloutSpoolDir = spool
			rootPublic, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			genesis, err := trust.ParseKeyring(rootPublic)
			if err != nil {
				t.Fatal(err)
			}
			bakedInputs = func() (bootstrapstart.BakedInputs, error) {
				return bootstrapstart.BakedInputs{Genesis: genesis, Identity: bootstrapstart.BakedIdentity{
					DeploymentID: "ts-560-test", Environment: "canary", Cell: "GRU"}}, nil
			}
			t.Cleanup(func() { rolloutSpoolDir, bakedInputs = previousSpool, previousBaked })

			if _, err := invoke("watchdog", "--root", root, "--owner", owner, "--unit", unit, "--config", config, "--restart"); err != nil {
				t.Fatal(err)
			}
			activation, pending, err := layout.Pending()
			if err != nil {
				t.Fatal(err)
			}
			data, replyErr := os.ReadFile(filepath.Join(root, rolloutexec.ReplyFile))
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
