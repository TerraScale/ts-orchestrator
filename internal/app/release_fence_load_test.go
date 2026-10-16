package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

// TS-719's first slice exercises the active service release, delivery, fence
// and automatic rollback engines with modeled members and HTTP routing. The
// live staging cell, real TerraBase data and OCI draining remain unqualified.
func TestTerraBaseReleaseFenceUnderLoad(t *testing.T) {
	for _, scenario := range []string{"upgrade", "canary failure", "member failure"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			kv, conn, js := fenceBroker(t)
			fence, cell, balancer, _, _ := newFenceTestWithStore(t, kv)
			cell.role, cell.environment = terrabase.Role, "canary"
			delete(balancer.sets, "ts-auth")
			spec, _ := fence.spec()
			spec.BackendSets = []cellspec.FencedSet{{Name: terrabase.Role, Port: 9465, MinServing: 2}}
			spec.Canary = &cellspec.Canary{Project: "traffic-test"}
			writer := &releaseLoadWriter{fenceCell: cell}
			if scenario == "member failure" {
				writer.failNode = "ctl-2"
			}
			public, private, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			keyID, err := protocol.KeyID(public)
			if err != nil {
				t.Fatal(err)
			}
			codec := delivery.Ed25519Codec{Cell: "gru", Actor: "ops", PrivateKey: private,
				Trusted:  map[string]delivery.TrustedSigner{keyID: {Actor: "ops", PublicKey: public}},
				Lifetime: time.Minute, MaxLifetime: time.Minute}
			service, err := delivery.Open(ctx, delivery.Config{Conn: conn, JS: js, Cell: "gru", Replicas: 1,
				Verifier: codec, ArtifactSigner: codec, ArtifactVerifier: codec, Fencer: fence.fencer, Planner: writer, Writer: writer,
				Authorize:         func(context.Context, string, delivery.Intent) error { return nil },
				AuthorizeArtifact: func(context.Context, string, delivery.ArtifactRecord) error { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- service.Run(ctx) }()
			defer func() { cancel(); <-done }()
			admit := func(data string) delivery.ArtifactRecord {
				t.Helper()
				record, claim, err := service.PrepareArtifact(ctx, strings.NewReader(data), delivery.ArtifactClaimRequest{
					Cell: "gru", Role: terrabase.Role, Environment: "canary",
					Source: delivery.ArtifactSource{Repository: terrabase.Repository, Commit: strings.Repeat("a", 40), TreeDigest: strings.Repeat("b", 64)}})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := service.AcceptArtifactClaim(ctx, claim); err != nil {
					t.Fatal(err)
				}
				return record
			}
			previous, candidate := admit("previous release"), admit("candidate release")
			writer.candidate = candidate.Digest
			cell.digests = map[uint64]string{6: previous.Digest, 7: candidate.Digest, 8: previous.Digest}
			var restarts []string
			cell.restarted = func(node string) { restarts = append(restarts, fmt.Sprintf("%s/%d", node, cell.release)) }

			var completed, failed atomic.Uint64
			edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				balancer.mu.Lock()
				defer balancer.mu.Unlock()
				for _, backend := range balancer.sets[terrabase.Role] {
					if backend.Serving() && !balancer.down[backend.Name()] {
						w.WriteHeader(http.StatusOK)
						return
					}
				}
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			t.Cleanup(edge.Close)
			client := edge.Client()
			client.Timeout = 5 * time.Second
			request := func() {
				response, err := client.Get(edge.URL)
				if err == nil {
					_, readErr := io.Copy(io.Discard, response.Body)
					err = errors.Join(readErr, response.Body.Close())
				}
				if err != nil || response.StatusCode != http.StatusOK {
					failed.Add(1)
				}
				completed.Add(1)
			}
			// The same counter must detect an outage before it can qualify a run.
			balancer.mu.Lock()
			for _, backend := range balancer.sets[terrabase.Role] {
				balancer.down[backend.Name()] = true
			}
			balancer.mu.Unlock()
			request()
			if failed.Load() != 1 {
				t.Fatal("traffic did not detect the all-backends-down negative control")
			}
			balancer.mu.Lock()
			clear(balancer.down)
			balancer.mu.Unlock()
			completed.Store(0)
			failed.Store(0)
			stop := make(chan struct{})
			var clients sync.WaitGroup
			for range 4 {
				clients.Go(func() {
					for {
						select {
						case <-stop:
							return
						default:
							request()
							time.Sleep(time.Millisecond)
						}
					}
				})
			}
			var once sync.Once
			finish := func() { once.Do(func() { close(stop); clients.Wait(); client.CloseIdleConnections() }) }
			t.Cleanup(finish)
			// At most four requests predate a transition. Twelve completions
			// therefore include at least eight fresh requests in every wait.
			fence.sleep = func(ctx context.Context, _ time.Duration) error {
				goal := completed.Load() + 12
				for completed.Load() < goal {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(time.Millisecond):
					}
				}
				return nil
			}
			gateCalls := 0
			canary := func(_ context.Context, target canaryTarget) map[string]string {
				cell.mu.Lock()
				defer cell.mu.Unlock()
				gateCalls++
				if target.Role != terrabase.Role || target.Node != "ctl-1" || len(cell.restarts) > 1 {
					t.Errorf("canary %+v ran after restarts %v", target, cell.restarts)
				}
				if scenario == "canary failure" && len(cell.restarts) == 1 {
					return map[string]string{checkDocuments: "injected candidate regression"}
				}
				return nil
			}
			intent := nativeIntent(candidate, nativeRelease{Role: terrabase.Role, Replicas: 3}, 7)
			intent.SchemaVersion, intent.OperationID, intent.AuthorityEpoch = delivery.SchemaVersion, entityid.Derive("test-operation", "traffic-upgrade"), 3
			state := serviceReleaseState{State: releasechannel.StateRolling, Actor: "ops", Digest: candidate.Digest,
				Previous: previous.Digest, Intent: &intent, IssuedAt: time.Now()}
			var revision uint64
			save := func(next serviceReleaseState) (err error) {
				revision, err = saveServiceRelease(ctx, kv, "traffic-test", next, revision)
				return err
			}
			if err := save(state); err != nil {
				t.Fatal(err)
			}
			// This modeled traffic fixture supplies test-only preparation/proofs;
			// signed profile history is exercised by the native app integrations.
			deployer := nativeDeployer{service: service, hosts: cell, sequence: fence.sequence, canary: canary,
				prepare: func(_ context.Context, i delivery.Intent, _, _ string) (delivery.Intent, *nativeRollbackTarget, error) {
					return i, &nativeRollbackTarget{Artifact: previous, ConfigDigest: intent.ConfigDigest, Replicas: 3}, nil
				},
				submit: func(ctx context.Context, i delivery.Intent) (delivery.Intent, string, error) {
					if i.OperationID == "" {
						i.OperationID = entityid.New()
						i.AuthorityEpoch = 3
					}
					fp, err := i.Fingerprint()
					if err != nil {
						return i, "", err
					}
					if err := fence.prepare(ctx, i); err != nil {
						return i, "", err
					}
					return i, fp, service.SubmitVerified(ctx, i, "ops")
				},
				observe: func(ctx context.Context, i delivery.Intent) (bool, error) {
					statuses, err := cell.ListHosts(ctx)
					if err != nil {
						return false, err
					}
					desired, err := cell.ListDesired(ctx, i.Role)
					if err != nil {
						return false, err
					}
					for j := range desired {
						desired[j].Cell, desired[j].Environment, desired[j].Digest = i.Cell, i.Environment, i.ArtifactDigest
					}
					for j := range statuses {
						s := &statuses[j]
						s.Verified, s.SessionExpiresAt = true, time.Now().Add(time.Minute)
						s.Registration = host.Registration{Cell: i.Cell, Node: s.Reports[0].Node, Environment: i.Environment, Roles: []string{i.Role}}
						s.Reports[0].Cell, s.Reports[0].SessionID, s.Reports[0].Epoch = i.Cell, entityid.Derive("test-session", s.Registration.Node), 3
					}
					nodes, err := nativeReady(statuses, desired, i, time.Now())
					return len(nodes) == i.DesiredReplicas, err
				},
				recovering: func(ctx context.Context, recovery delivery.Intent, cause error) (delivery.Intent, error) {
					recovery.OperationID, recovery.AuthorityEpoch = entityid.New(), 3
					state.Rollback, state.Reason = &recovery, cause.Error()
					if err := markKnownBad(ctx, kv, terrabase.Role, candidate.Digest, cause); err != nil {
						return recovery, err
					}
					return recovery, save(state)
				}}
			gateErr := deployer.roll(ctx, intent, 10*time.Second, io.Discard)
			if gateErr == nil {
				state.State = releasechannel.StateComplete
			} else {
				state.State, state.Reason = releasechannel.StateFailed, gateErr.Error()
			}
			finish()
			if err != nil {
				t.Fatal(err)
			}
			wantState, wantDigest := releasechannel.StateComplete, candidate.Digest
			wantRestarts := []string{"ctl-1/7", "ctl-2/7", "ctl-3/7"}
			if scenario != "upgrade" {
				wantState, wantDigest = releasechannel.StateFailed, previous.Digest
				wantRestarts = []string{"ctl-1/7", "ctl-1/8", "ctl-2/8", "ctl-3/8"}
				if scenario == "member failure" {
					wantRestarts = []string{"ctl-1/7", "ctl-2/7", "ctl-2/8", "ctl-1/8", "ctl-3/8"}
				}
				if state.Rollback == nil || state.Rollback.ArtifactDigest != previous.Digest ||
					!strings.Contains(state.Reason, "was rolled back to "+previous.Digest) {
					t.Fatalf("automatic rollback did not finish: %+v", state)
				}
				if _, found, err := knownBad(ctx, kv, terrabase.Role, candidate.Digest); err != nil || !found {
					t.Fatalf("candidate was not marked known bad: %v %v", found, err)
				}
			}
			if state.State != wantState || !slices.Equal(restarts, wantRestarts) || gateCalls < 2 {
				t.Fatalf("state=%s restarts=%v canary calls=%d, want %s %v", state.State, restarts, gateCalls, wantState, wantRestarts)
			}
			writer.mu.Lock()
			applied := slices.Clone(writer.applied)
			writer.mu.Unlock()
			for generation, digest := range cell.digests {
				if generation == 6 || generation == 8 && scenario == "upgrade" {
					continue
				}
				for _, node := range cell.nodes {
					if !slices.ContainsFunc(applied, func(desired host.Desired) bool {
						return desired.Node == node && desired.Generation == generation && desired.Digest == digest
					}) {
						t.Fatalf("delivery missing %s/%d digest %s: %+v", node, generation, digest, applied)
					}
				}
			}
			backends, err := balancer.ListBackends(ctx, spec.LoadBalancerID, terrabase.Role)
			if err != nil || len(backends) != 3 {
				t.Fatalf("final backends: %+v, %v", backends, err)
			}
			for _, backend := range backends {
				if !backend.Serving() {
					t.Errorf("backend remains out of rotation: %+v", backend)
				}
			}
			keys, err := kv.ListKeys(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for key := range keys.Keys() {
				if strings.HasPrefix(key, "fence.") || strings.HasPrefix(key, "fenced.") {
					t.Errorf("release fence remains: %s", key)
				}
			}
			statuses, err := cell.ListHosts(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, status := range statuses {
				for _, report := range status.Reports {
					if report.Digest != wantDigest || report.State != "running" {
						t.Fatalf("final member does not serve %s: %+v", wantDigest, report)
					}
				}
			}
			if completed.Load() < 40 || failed.Load() != 0 {
				t.Fatalf("%d of %d requests failed", failed.Load(), completed.Load())
			}
			t.Logf("%s: %d requests, zero failures", scenario, completed.Load())
		})
	}
}

// releaseLoadWriter models delivery of a new release to all three hosts.
// The real fence's restart permit still controls when each report changes.
type releaseLoadWriter struct {
	*fenceCell
	candidate, failNode string
	applied             []host.Desired
}

func (w *releaseLoadWriter) Plan(_ context.Context, intent delivery.Intent) ([]host.Desired, error) {
	var desired []host.Desired
	for _, node := range w.nodes {
		desired = append(desired, host.Desired{Cell: intent.Cell, Node: node, Role: intent.Role, Environment: intent.Environment,
			Digest: intent.ArtifactDigest, Generation: intent.Generation, AuthorityEpoch: intent.AuthorityEpoch})
	}
	return desired, nil
}

func (w *releaseLoadWriter) ApplyDesired(_ context.Context, desired host.Desired) (host.Receipt, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.applied = append(w.applied, desired)
	if generation := releaseOf(desired.Generation); generation != w.release {
		w.release, w.restarts = generation, nil
	}
	w.broken = map[string]bool{}
	if desired.Digest == w.candidate && w.failNode != "" {
		w.broken[w.failNode] = true
	}
	return host.Receipt{}, nil
}
