package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/client"
	network "git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

func TestNetBirdRolloutPersistsProgressAndRejectsFencedLeader(t *testing.T) {
	kv := fenceKV(t)
	lease := &fenceLease{}
	r := netbirdRollout{fence: &releaseFence{kv: kv, fencer: lease}}
	before := network.Record{ID: "4845ZN4B5KA6F2FCQQZE93Y54S", Node: "node-a", Previous: "0.79.0", Phase: "check"}
	if err := saveNetBirdTestRecord(t.Context(), &r, 3, before); err != nil {
		t.Fatal(err)
	}
	restarted := netbirdRollout{fence: &releaseFence{kv: kv, fencer: lease}}
	var after network.Record
	if err := restarted.load(t.Context(), netbirdRecordKey, &after); err != nil || after.ID != before.ID || after.Node != before.Node || after.Phase != before.Phase {
		t.Fatalf("leader did not resume: %+v %v", after, err)
	}
	lease.lost = true
	before.Node = "node-b"
	if err := saveNetBirdTestRecord(t.Context(), &r, 3, before); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("deposed leader saved another node: %v", err)
	}
	if err := restarted.load(t.Context(), netbirdRecordKey, &after); err != nil || after.Node != "node-a" {
		t.Fatal("deposed leader changed active node")
	}
}

func TestNetBirdPinWaitsForBothArtifactsBeforeDrain(t *testing.T) {
	r, pin, _ := netbirdArtifactTest(t, "")
	r.services.current.NetBird = &cellspec.NetBird{Pin: pin}
	for _, architecture := range []string{"arm64", "amd64"} {
		archive, err := pin.Archive(architecture)
		if err != nil {
			t.Fatal(err)
		}
		// With no fence configured, reaching the drain prerequisites would
		// return a different error. A missing artifact must hold first.
		if err := r.preflight(t.Context(), "node-a"); err == nil || !strings.Contains(err.Error(), "not staged") {
			t.Fatalf("missing artifact did not hold before drain: %v", err)
		}
		if _, err := r.artifacts.PutBytes(t.Context(), "sha256-"+archive.BinarySHA256, netbirdArtifactELF(architecture)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.artifactsReady(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := r.artifacts.Delete(t.Context(), "sha256-"+pin.Archives.Arm64.BinarySHA256); err != nil {
		t.Fatal(err)
	}
	if err := r.artifactsReady(t.Context()); err == nil {
		t.Fatal("deleted artifact was considered staged")
	}
}

func TestNetBirdPinRemovalFinishesExistingTransaction(t *testing.T) {
	pin, err := client.LoadPin("../../deploy/image/image-inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	r := netbirdRollout{fence: &releaseFence{kv: fenceKV(t), fencer: &fenceLease{}}, services: &specRegistry{}}
	record := network.Record{ID: "60YZ75PP1XJESPGSK8EFF8GQNF", Node: "node-a", Phase: "confirm", Target: network.Target{Pin: pin}}
	if err := saveNetBirdTestRecord(t.Context(), &r, 3, record); err != nil {
		t.Fatal(err)
	}
	if target, err := r.target(t.Context()); err != nil || target == nil || target.Pin != pin {
		t.Fatalf("removed pin abandoned transaction: %+v %v", target, err)
	}
	status := network.Status{Version: "0.80.0", ObservedAt: time.Now().UTC()}
	if _, err := r.Exchange(t.Context(), host.Registration{Node: "node-a"}, status); err != nil {
		t.Fatal(err)
	}
	if observed, err := r.status(t.Context(), "node-a"); err != nil || observed.Version != status.Version {
		t.Fatalf("removed pin stopped worker exchange: %+v %v", observed, err)
	}
	record.Phase = "done"
	if err := saveNetBirdTestRecord(t.Context(), &r, 3, record); err != nil {
		t.Fatal(err)
	}
	if target, err := r.target(t.Context()); err != nil || target != nil {
		t.Fatalf("disabled pin started another transaction: %+v %v", target, err)
	}
}

func TestNetBirdArtifactCollectionRetainsInFlightPin(t *testing.T) {
	pin, err := client.LoadPin("../../deploy/image/image-inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	previous := pin
	previous.Archives.Arm64.BinarySHA256 = strings.Repeat("a", 64)
	previous.Archives.AMD64.BinarySHA256 = strings.Repeat("b", 64)
	r := netbirdRollout{cell: "gru", fence: &releaseFence{kv: fenceKV(t), fencer: &fenceLease{}},
		services: &specRegistry{current: cellspec.Spec{NetBird: &cellspec.NetBird{Pin: pin}}}}
	record := network.Record{ID: "1P4DT7KVBAJVZ9B4AJPV2KEYWF", Phase: "rollback-check", Target: network.Target{Pin: previous}}
	if err := saveNetBirdTestRecord(t.Context(), &r, 3, record); err != nil {
		t.Fatal(err)
	}
	uses, err := r.artifactsInUse(t.Context())
	if err != nil || len(uses) != 4 || uses[2].Digest != previous.Archives.Arm64.BinarySHA256 {
		t.Fatalf("in-flight artifact discarded after pin change: %+v %v", uses, err)
	}
	record.Phase = "done"
	if err := saveNetBirdTestRecord(t.Context(), &r, 3, record); err != nil {
		t.Fatal(err)
	}
	uses, err = r.artifactsInUse(t.Context())
	if err != nil || len(uses) != 2 {
		t.Fatalf("completed artifact references: %+v %v", uses, err)
	}
	lease := r.fence.fencer.(*fenceLease)
	lease.mu.Lock()
	lease.netbird.Payload = []byte("corrupt")
	lease.mu.Unlock()
	if _, err := r.artifactsInUse(t.Context()); err == nil {
		t.Fatal("collection continued through corrupt rollout state")
	}
}

func TestMeshReadinessDoesNotFollowRedirectsOrAcceptFailure(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable, http.StatusFound} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/readyz" {
					t.Error("did not probe readiness")
				}
				w.Header().Set("Location", "https://example.invalid")
				w.WriteHeader(status)
			}))
			defer server.Close()
			address, port, _ := net.SplitHostPort(server.Listener.Addr().String())
			number, _ := strconv.Atoi(port)
			err := meshReady(t.Context(), address, number, nil)
			if (err == nil) != (status == http.StatusOK) {
				t.Fatalf("HTTP %d readiness result %v", status, err)
			}
		})
	}
}

func TestNetBirdLeaderCannotConfirmOnlyItsLocallyRoutedMeshIP(t *testing.T) {
	r := netbirdRollout{cell: "gru", cfg: Config{NATS: natscell.Config{Instance: "controller-a"}},
		services: &specRegistry{current: cellspec.Spec{HostGrants: []cellspec.HostGrant{{Node: "node-a", Controller: "controller-a"}}}},
		fence: &releaseFence{spec: func() (*cellspec.ReleaseFence, map[string]string) {
			return &cellspec.ReleaseFence{}, map[string]string{"node-a": "10.251.0.11"}
		}}}
	status := network.Status{Version: "0.80.0", Connected: true, IP: "10.200.1.2", DNS: "node-a.nb.ts.internal"}
	if err := r.healthy(t.Context(), "node-a", status, time.Time{}); err == nil || !strings.Contains(err.Error(), "remote controller peer") {
		t.Fatalf("locally routed mesh address skipped peer verification: %v", err)
	}
}

func TestNetBirdBootstrapMissingLeaderHoldsBeforeDrain(t *testing.T) {
	for _, state := range []string{"missing", "installed-unhealthy", "unknown", "pending", "failed"} {
		t.Run(state, func(t *testing.T) {
			leader, peer := netbirdRecoveryControllers(t)
			sub, err := peer.serveRecovery(t.Context(), func(context.Context, string) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sub.Unsubscribe() })
			if err := peer.conn.FlushTimeout(time.Second); err != nil {
				t.Fatal(err)
			}
			pin := netbirdArtifactTestPin(t)
			leader.services.current.NetBird = &cellspec.NetBird{Pin: pin}
			leader.fence.kv = fenceKV(t)
			leader.artifacts = netbirdArtifactStore(t, leader.conn)
			stageTestNetbirdArtifacts(t, leader.artifacts, pin)
			missing := network.Status{Missing: true, ObservedAt: time.Now().UTC()}
			other := missing
			switch state {
			case "installed-unhealthy":
				other.Missing, other.Version = false, "0.79.0"
			case "unknown":
				other.Missing = false
			case "pending":
				other.Pending = "unfinished"
			case "failed":
				other.Error = "failed observation"
			}
			for node, status := range map[string]network.Status{"node-a": missing, "node-b": other} {
				if err := leader.saveAt(t.Context(), 3, "netbird.status."+node, status); err != nil {
					t.Fatal(err)
				}
			}
			if err := leader.preflight(t.Context(), "node-b"); err == nil || !strings.Contains(err.Error(), "probing leader has no working mesh client") {
				t.Fatalf("missing leader admitted unconfirmable bootstrap %s: %v", state, err)
			}
			if state == "missing" {
				r := network.Reconciler{
					Load:   func(context.Context) (network.Record, error) { return network.Record{}, nil },
					Status: leader.status, Preflight: leader.preflight,
					Save: func(context.Context, network.Record) error {
						t.Fatal("bootstrap saved a transaction without a probing leader")
						return nil
					},
					Drain: func(context.Context, string) error { t.Fatal("bootstrap drained without a probing leader"); return nil },
				}
				if err := r.Tick(t.Context(), network.Target{Pin: pin}, []string{"node-b", "node-a"}); err == nil {
					t.Fatal("all-missing cell admitted a rollout")
				}
			}
			if keys, err := leader.fence.keys(t.Context(), fencedKey("*")); err != nil || len(keys) != 0 {
				t.Fatalf("bootstrap changed fence state: %v %v", keys, err)
			}
			var record network.Record
			if err := leader.load(t.Context(), netbirdRecordKey, &record); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("bootstrap created a transaction: %+v %v", record, err)
			}
		})
	}
}

func TestNetBirdDrainDeadlineIncludesGraceAndAllowsRecoveryRetries(t *testing.T) {
	for _, tc := range []struct {
		name, phase string
		grace       int
		expired     bool
		budget      time.Duration
	}{
		{"default-grace", "drain", 0, false, 45 * time.Second},
		{"maximum-grace", "drain", 300, false, 330 * time.Second},
		{"rollback-after-quorum-repair", "rollback", 0, true, 45 * time.Second},
		{"rollback-check-redrain", "rollback-check", 0, true, 45 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _, _, _, _ := newFenceTest(t)
			spec, _ := f.spec()
			spec.DrainGraceSeconds = tc.grace
			n := netbirdRollout{fence: f}
			deadline := time.Now().Add(10 * time.Minute)
			if tc.expired {
				deadline = time.Now().Add(-time.Minute)
			}
			if err := saveNetBirdTestRecord(t.Context(), &n, 3, network.Record{ID: "4H828TAVQA1MJ7WHF4634YW4B6", Node: "ctl-1", Phase: tc.phase, Deadline: deadline}); err != nil {
				t.Fatal(err)
			}
			stopped := errors.New("captured bounded drain context")
			f.open = func(ctx context.Context) (lb.API, error) {
				bounded, ok := ctx.Deadline()
				if remaining := time.Until(bounded); !ok || remaining < tc.budget-time.Second || remaining > tc.budget {
					t.Fatalf("drain budget=%v, expected %v (deadline present=%t)", remaining, tc.budget, ok)
				}
				return nil, stopped
			}
			if err := n.drainNode(t.Context(), 3, "ctl-1"); !errors.Is(err, stopped) {
				t.Fatalf("drain did not reach bounded provider call: %v", err)
			}
		})
	}
}

func TestNetBirdPartialDrainExpiresWithoutRelaxingQuorumAndCanRecover(t *testing.T) {
	f, _, api, _, _ := newFenceTest(t)
	n := netbirdRollout{fence: f}
	// TerraBase can drain, but ts-auth has no healthy alternative to ctl-2.
	api.down[lb.Backend{IP: fenceAddresses["ctl-3"], Port: 8080}.Name()] = true
	record := network.Record{ID: "4H828TAVQA1MJ7WHF4634YW4B6", Node: "ctl-2", Phase: "drain", Deadline: time.Now().Add(100 * time.Millisecond)}
	if err := saveNetBirdTestRecord(t.Context(), &n, 3, record); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- n.drainNode(t.Context(), 3, "ctl-2") }()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("partial drain ignored persisted deadline: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("quorum wait blocked the reconciler past its persisted deadline")
	}
	if len(api.log) != 1 || !strings.HasPrefix(api.log[0], "terrabase ") || !strings.HasSuffix(api.log[0], " drain") {
		t.Fatalf("partial drain bypassed quorum: %v", api.log)
	}
	// Recovery retries need a fresh bounded attempt even after that deadline.
	record.Phase = "rollback"
	if err := saveNetBirdTestRecord(t.Context(), &n, 3, record); err != nil {
		t.Fatal(err)
	}
	clear(api.down)
	var grace time.Duration
	f.sleep = func(ctx context.Context, d time.Duration) error { grace = d; return ctx.Err() }
	if err := n.drainNode(t.Context(), 3, "ctl-2"); err != nil {
		t.Fatalf("repaired quorum could not re-establish the rollback fence: %v", err)
	}
	if grace != defaultFenceGrace {
		t.Fatalf("recovery did not allow the configured drain grace: %v", grace)
	}
	for _, set := range api.sets {
		for _, backend := range set {
			if backend.IP == fenceAddresses["ctl-2"] && backend != backend.Fenced(true, true) {
				t.Fatalf("rollback would restart an undrained backend: %+v", backend)
			}
		}
	}
}
