//go:build linux

package host

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// Any native lifecycle call panics through the absent embedded runner.
type sessionOnlyRunner struct{ Runner }

func TestSessionRuntimeDeliversMaterialAndFencesRevokedHostWithoutNativeRunner(t *testing.T) {
	fixture := newFunctionMaterialTransport(t)
	fixture.controller.functionMaterial = fixture.current
	agent := fixture.startUnacquired(t)
	agent.runner = sessionOnlyRunner{}
	followersStarted := make(chan struct{}, 2)
	followersCanceled := make(chan struct{}, 2)
	followersRelease := make(chan struct{})
	releaseFollowers := sync.OnceFunc(func() { close(followersRelease) })
	newFollower := func() (func(context.Context), <-chan struct{}) {
		finished := make(chan struct{})
		return func(ctx context.Context) {
			defer close(finished)
			followersStarted <- struct{}{}
			<-ctx.Done()
			followersCanceled <- struct{}{}
			<-followersRelease
		}, finished
	}
	rollout, rolloutFinished := newFollower()
	netbird, netbirdFinished := newFollower()
	agent.cfg.FollowRollouts = func(ctx context.Context, _ RolloutSession) { rollout(ctx) }
	agent.cfg.FollowNetBird = func(ctx context.Context, _ NetBirdSession) { netbird(ctx) }
	journalStarted := make(chan struct{})
	agent.logsCommand = func(ctx context.Context) (io.ReadCloser, error) {
		close(journalStarted)
		return blockingJournal(ctx), nil
	}
	ticks := make(chan time.Time)
	agent.logsTick = ticks
	subject := protocol.AgentObservation(agent.cfg.Cell, agent.cfg.NATSUserPublicKey, "logs")
	subscription, err := fixture.conn.SubscribeSync(subject)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = subscription.Unsubscribe() })
	if err := fixture.conn.FlushTimeout(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	publisherStarted := make(chan struct{})
	publisherFinished := make(chan struct{})
	publisherRelease := make(chan struct{})
	releasePublisher := sync.OnceFunc(func() { close(publisherRelease) })
	startedPublish := sync.OnceFunc(func() { close(publisherStarted) })
	finishedPublish := sync.OnceFunc(func() { close(publisherFinished) })
	published := make(chan error, 1)
	agent.logsPublish = func(subject string, data []byte) error {
		startedPublish()
		defer finishedPublish()
		<-publisherRelease
		err := fixture.conn.Publish(subject, data)
		if err == nil {
			err = fixture.conn.FlushTimeout(5 * time.Second)
		}
		if err == nil {
			message, receiveErr := subscription.NextMsg(5 * time.Second)
			err = receiveErr
			if err == nil && (message.Subject != subject || !bytes.Equal(message.Data, data)) {
				err = errors.New("real NATS log window differs from publication")
			}
		}
		select {
		case published <- err:
		default:
		}
		return err
	}
	ready := make(chan struct{})
	agent.cfg.Initialized = func() { close(ready) }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		done <- agent.RunSession(ctx)
	}()
	t.Cleanup(func() {
		releaseFollowers()
		releasePublisher()
		cancel()
		select {
		case <-finished:
		case <-time.After(15 * time.Second):
			t.Error("session workers did not finish during cleanup")
		}
		// Join the gates independently too, so a broken RunSession cannot let
		// the fixture close NATS while its failed regression still publishes.
		select {
		case <-ready:
			for _, completed := range []<-chan struct{}{rolloutFinished, netbirdFinished} {
				select {
				case <-completed:
				case <-time.After(5 * time.Second):
					t.Error("session follower did not finish during cleanup")
				}
			}
		default:
		}
		select {
		case <-publisherStarted:
			select {
			case <-publisherFinished:
			case <-time.After(15 * time.Second):
				t.Error("log publisher did not finish during cleanup")
			}
		default:
		}
	})
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("session runtime exited before readiness: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("session runtime did not establish its signed host session")
	}
	files, _, err := agent.CurrentFunctionFiles(t.Context(), fixture.binding)
	if err != nil || !bytes.Equal(files["module.wasm"], fixture.files["module.wasm"]) {
		t.Fatalf("same session did not deliver admitted function material: %v", err)
	}
	for range 2 {
		select {
		case <-followersStarted:
		case <-time.After(5 * time.Second):
			t.Fatal("session follower did not start")
		}
	}
	select {
	case <-journalStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("session journal did not start")
	}
	// The signed controller and session use the real clock. Wait for its next
	// minute instead of advancing the agent's clock past the execution lease.
	boundary := time.Now().Truncate(time.Minute).Add(time.Minute)
	select {
	case <-time.After(time.Until(boundary)):
	case err := <-done:
		t.Fatalf("session exited before the log window: %v", err)
	case <-time.After(65 * time.Second):
		t.Fatal("real log minute did not end")
	}
	select {
	case ticks <- boundary:
	case <-time.After(5 * time.Second):
		t.Fatal("log window worker did not accept its tick")
	}
	select {
	case <-publisherStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("real log window did not reach the publisher")
	}
	statuses, err := fixture.controller.ListHosts(t.Context())
	if err != nil || len(statuses) != 1 {
		t.Fatalf("read real host before revocation: %v", err)
	}
	registration := statuses[0].Registration
	registration.Generation++
	if _, err := fixture.controller.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case <-followersCanceled:
		case <-time.After(5 * time.Second):
			t.Fatal("revoked session did not cancel its follower")
		}
	}
	select {
	case err := <-done:
		t.Fatalf("session returned with active followers: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	releaseFollowers()
	for _, completed := range []<-chan struct{}{rolloutFinished, netbirdFinished} {
		select {
		case <-completed:
		case <-time.After(5 * time.Second):
			t.Fatal("released session follower did not finish")
		}
	}
	select {
	case err := <-done:
		t.Fatalf("session returned with an active log publisher: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	releasePublisher()
	select {
	case err := <-published:
		if err != nil {
			t.Fatalf("real NATS log window was not observed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("real NATS log window was not observed")
	}
	select {
	case <-publisherFinished:
	case <-time.After(5 * time.Second):
		t.Fatal("released log publisher did not finish")
	}
	select {
	case err := <-done:
		if err == nil || errors.Is(err, context.Canceled) {
			t.Fatalf("revoked host did not fail its session: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session runtime did not fence the revoked registration")
	}
	if _, _, err := agent.CurrentFunctionFiles(t.Context(), fixture.binding); err == nil {
		t.Fatal("revoked session still delivered function material")
	}
	if _, err := agent.RuntimeWorkerIdentity("accepted-instance", "accepted-node"); err == nil {
		t.Fatal("revoked session still exposed a runtime identity lease")
	}
}
