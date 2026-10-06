package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/releasechannel"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
)

// TestReleaseChannelRollsCIReleasesOutRegionByRegion runs CI's automatic
// fleet deployment end to end against two regions of three real brokers:
// CI signs each run per region, uploads the binary and publishes the
// region's channel, canary first, and waits for the region's report. Each
// region's authority leader verifies the channel, publishes the run as the
// cell's next generation and rolls it out one controller per wave, the seed
// last; each controller relays its steps and fetches the binary from the
// channel for its node's root step agent, which stages it only after the
// receipt verifies against the node's roots. A run that never becomes
// healthy is rolled back in the canary, reported failed, and stops the
// fleet rollout before the next region sees it.
func TestReleaseChannelRollsCIReleasesOutRegionByRegion(t *testing.T) {
	tier.Integration(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	root := t.TempDir()
	_, responseKey := testEd25519(t, root, "controller.key")
	operatorPublic, _ := testEd25519(t, root, "operator.key")
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase"}, Environments: []string{"production"}}
	signer := newReleaseSigner(t)
	contents := map[string][]byte{}
	binaries := map[string]string{}
	for _, name := range []string{"from", "good", "bad"} {
		contents[name] = []byte("orchestrator release " + name)
		binaries[name] = filepath.Join(root, name+".bin")
		if err := os.WriteFile(binaries[name], contents[name], 0o755); err != nil {
			t.Fatal(err)
		}
	}
	starts := &rolloutStartLog{}
	regions := []string{"gru", "sfo"}
	buckets := map[string]*channelBucket{}
	cells := map[string]*rolloutTestCell{}
	for _, region := range regions {
		bucket := newChannelBucket()
		buckets[region] = bucket
		location := releasechannel.Location{Client: bucket, Namespace: "ns", Bucket: region + "-1-head"}
		cells[region] = startRolloutTestCell(t, ctx, rolloutTestCellConfig{root: root, cell: region,
			ids: []string{region + "-ctl-a", region + "-ctl-b", region + "-ctl-c"}, responseKey: responseKey, grant: grant,
			services: signer.services(t),
			binaries: binaries, starts: starts,
			verifier: selfupdate.ReceiptPolicy{Roots: signer.roots, Environment: "production",
				Cell: strings.ToUpper(region), Architecture: goruntime.GOARCH, AllowScopedAutoSign: true},
			configure: func(c *rolloutControl) {
				c.follow = true
				c.channel = &channelSource{location: &location}
				c.channelInterval = 300 * time.Millisecond
			}})
	}
	// The canary's reports are published for fan-in across regions.
	reports, err := cells["gru"].runtimes[1].Conn().SubscribeSync(protocol.ReleaseStatusSubject("gru"))
	if err != nil {
		t.Fatal(err)
	}
	// deploy is CI's region loop (ts-orch release deploy).
	deploy := func(run int64, name string) error {
		for _, region := range regions {
			channel := signer.channel(t, strings.ToUpper(region), run, contents[name])
			location := releasechannel.Location{Client: buckets[region], Namespace: "ns", Bucket: region + "-1-head"}
			object := releasechannel.BinaryObject(digestOf(contents[name]))
			if _, err := buckets[region].PutObject(ctx, objectstorage.PutObjectRequest{ObjectName: &object,
				PutObjectBody: io.NopCloser(bytes.NewReader(contents[name]))}); err != nil {
				return err
			}
			if err := releasechannel.Publish(ctx, location, channel); err != nil {
				return err
			}
			var progress bytes.Buffer
			err := releasechannel.Await(ctx, location, channel, 200*time.Millisecond, time.Now().Add(2*time.Minute), &progress)
			t.Logf("run %d %s:\n%s", run, region, progress.String())
			if err != nil {
				return fmt.Errorf("fleet rollout stopped: %w", err)
			}
		}
		return nil
	}
	settled := func(region, name string) {
		t.Helper()
		for id, unit := range cells[region].units {
			for !unit.settledOn(digestOf(contents[name])) {
				if ctx.Err() != nil {
					t.Fatalf("unit %s did not settle on %s; starts %v", id, name, starts.all())
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	// Run 1 reaches every region, one controller per wave and the seed last.
	if err := deploy(1, "good"); err != nil {
		t.Fatal(err)
	}
	for _, region := range regions {
		settled(region, "good")
		order := slices.DeleteFunc(starts.on(digestOf(contents["good"])), func(unit string) bool {
			return !strings.HasPrefix(unit, region+"-")
		})
		if !slices.Equal(order, []string{region + "-ctl-b", region + "-ctl-c", region + "-ctl-a"}) {
			t.Fatalf("%s controllers moved as %v, want one per wave and the seed last", region, order)
		}
	}

	// Run 2 never becomes healthy: the canary region rolls it back and
	// reports it failed, which stops the fleet rollout.
	if err := deploy(2, "bad"); !errors.Is(err, releasechannel.ErrFailed) {
		t.Fatalf("deployment of a run that never became healthy = %v", err)
	}
	settled("gru", "good")
	if moved := starts.on(digestOf(contents["bad"])); !slices.Equal(moved, []string{"gru-ctl-b"}) {
		t.Fatalf("units that ran the bad release = %v, want the canary's first controller only", moved)
	}
	if bad, err := cells["gru"].units["gru-ctl-b"].layout.KnownBad(); err != nil || !bad[digestOf(contents["bad"])] {
		t.Fatalf("the canary's node does not refuse the bad release: %v %v", bad, err)
	}
	status, _ := buckets["gru"].status(t)
	if status.RunNumber != 2 || status.State != releasechannel.StateFailed || !strings.Contains(status.Reason, "rolled-back") {
		t.Fatalf("canary status = %+v", status)
	}
	sfo := releasechannel.Location{Client: buckets["sfo"], Namespace: "ns", Bucket: "sfo-1-head"}
	if channel, _, err := releasechannel.ReadChannel(ctx, sfo); err != nil || channel.RunNumber != 1 {
		t.Fatalf("the next region saw the failed run: %+v %v", channel, err)
	}
	settled("sfo", "good")
	for published := false; !published; {
		message, err := reports.NextMsg(10 * time.Second)
		if err != nil {
			t.Fatalf("no failed report of run 2 on %s: %v", protocol.ReleaseStatusSubject("gru"), err)
		}
		var report releasechannel.Status
		if err := json.Unmarshal(message.Data, &report); err != nil {
			t.Fatal(err)
		}
		published = report.RunNumber == 2 && report.State == releasechannel.StateFailed
	}
	// The canary's leader shows the report in ts-orch rollout status.
	for _, control := range cells["gru"].controls {
		if reported := control.reported.Load(); reported != nil && reported.RunNumber == 2 {
			return
		}
	}
	t.Fatal("no gru controller holds the failed report for ts-orch rollout status")
}
