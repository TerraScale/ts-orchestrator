//go:build linux

package host

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

type clockCloseRunner struct {
	*memoryRunner
	closes  atomic.Int32
	entered chan struct{}
	release <-chan struct{}
}

func (r *clockCloseRunner) Close(ctx context.Context) error {
	r.closes.Add(1)
	close(r.entered)
	select {
	case <-r.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return r.memoryRunner.Close(ctx)
}

func TestHostClockRejectsStartupAndSession(t *testing.T) {
	c, conn, _, _, responseKey := testController(t)
	hostKey := registerTestHost(t, c)
	runner := &memoryRunner{observed: map[string]Observation{"terrabase": {Role: "terrabase", Running: true}}}
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return errors.New("clock unsynchronized") },
		WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"},
		Conn: conn, Identity: hostKey, ControllerPublicKey: responseKey.Public().(ed25519.PublicKey), Runner: runner,
		InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.acquire(t.Context()); err == nil || !strings.Contains(err.Error(), "clock") {
		t.Fatalf("bad clock acquired session: %v", err)
	}
	if err := agent.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "clock") {
		t.Fatalf("bad clock started host: %v", err)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.observed["terrabase"].Running || agent.session.Epoch != 0 {
		t.Fatal("bad clock retained native role or signed session")
	}
}

func TestPartitionedHostFencesOnClockLossOrMonotonicExpiry(t *testing.T) {
	for _, mode := range []string{"clock loss", "backward wall step"} {
		t.Run(mode, func(t *testing.T) {
			c, conn, _, _, responseKey := testController(t)
			hostKey := registerTestHost(t, c)
			controllerCtx, stopController := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- c.Run(controllerCtx) }()
			select {
			case <-c.Ready():
			case <-t.Context().Done():
				t.Fatal(t.Context().Err())
			}
			var badClock atomic.Bool
			runner := &memoryRunner{observed: make(map[string]Observation)}
			agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error {
				if badClock.Load() {
					return errors.New("clock unsynchronized")
				}
				return nil
			}, WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"},
				Conn: conn, Identity: hostKey, ControllerPublicKey: responseKey.Public().(ed25519.PublicKey), Runner: runner,
				InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t)})
			if err != nil {
				t.Fatal(err)
			}
			if err := agent.acquire(t.Context()); err != nil {
				t.Fatal(err)
			}
			runner.mu.Lock()
			runner.observed["terrabase"] = Observation{Role: "terrabase", Running: true}
			runner.mu.Unlock()
			stopController()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("controller did not stop")
			}
			agent.cfg.Conn = nil // No renewal path remains during the partition.
			if mode == "clock loss" {
				badClock.Store(true)
			} else {
				agent.wallNow = func() time.Time { return time.Now().Add(-time.Hour) }
				agent.mu.Lock()
				agent.sessionSafeUntil = time.Now().Add(-time.Millisecond)
				current := agent.session
				agent.mu.Unlock()
				if !sessionUsableUntil(current, agent.wallTime()) {
					t.Fatal("backward wall step did not make the absolute lease appear usable")
				}
			}
			monitorCtx, cancel := context.WithCancel(t.Context())
			lost := make(chan error, 1)
			go agent.maintainSession(monitorCtx, cancel, lost)
			select {
			case err := <-lost:
				if err == nil {
					t.Fatal("partitioned host stopped without failure")
				}
			case <-time.After(time.Second):
				t.Fatal("partitioned host retained native role after clock safety loss")
			}
			runner.mu.Lock()
			running := runner.observed["terrabase"].Running
			runner.mu.Unlock()
			if running || !agent.sessionLost.Load() {
				t.Fatal("clock safety loss did not close the native runner")
			}
		})
	}
}

func TestClockRecheckBlocksNativeApply(t *testing.T) {
	c, conn, store, _, responseKey := testController(t)
	hostKey := registerTestHost(t, c)
	artifact := []byte("#!/bin/sh\nexit 0\n")
	digest := sha256.Sum256(artifact)
	digestHex := hex.EncodeToString(digest[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digestHex, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyDesired(t.Context(), Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase",
		Digest: digestHex, Generation: 1, AuthorityEpoch: 1}); err != nil {
		t.Fatal(err)
	}
	controllerCtx, stopController := context.WithCancel(t.Context())
	defer stopController()
	done := make(chan error, 1)
	go func() { done <- c.Run(controllerCtx) }()
	select {
	case <-c.Ready():
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	var checks atomic.Int32
	var enforce atomic.Bool
	runner := &memoryRunner{observed: make(map[string]Observation)}
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error {
		if enforce.Load() && checks.Add(1) >= 2 {
			return errors.New("clock unsynchronized before apply")
		}
		return nil
	}, WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"},
		Conn: conn, Identity: hostKey, ControllerPublicKey: responseKey.Public().(ed25519.PublicKey), Runner: runner,
		InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	checks.Store(0)
	enforce.Store(true)
	if err := agent.reconcile(t.Context(), "terrabase"); err == nil || !strings.Contains(err.Error(), "clock unsynchronized before apply") {
		t.Fatalf("clock loss before native Apply was not enforced: %v", err)
	}
	runner.mu.Lock()
	applied := runner.applied
	runner.mu.Unlock()
	if applied != 0 {
		t.Fatal("native Apply ran after clock became unhealthy")
	}
	stopController()
	<-done
}

func TestBlockedRenewalClockWatchdogStopsOnce(t *testing.T) {
	for _, concurrentFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "watchdog", true: "watchdog_and_renewal"}[concurrentFailure], func(t *testing.T) {
			c, conn, _, _, responseKey := testController(t)
			hostKey := registerTestHost(t, c)
			controllerCtx, stopController := context.WithCancel(t.Context())
			controllerDone := make(chan error, 1)
			go func() { controllerDone <- c.Run(controllerCtx) }()
			select {
			case <-c.Ready():
			case <-t.Context().Done():
				t.Fatal(t.Context().Err())
			}
			var badClock atomic.Bool
			releaseClose := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseClose) }) }
			t.Cleanup(release)
			runner := &clockCloseRunner{memoryRunner: &memoryRunner{observed: make(map[string]Observation)}, entered: make(chan struct{}), release: releaseClose}
			agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error {
				if badClock.Load() {
					return errors.New("clock unsynchronized")
				}
				return nil
			}, WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"},
				Conn: conn, Identity: hostKey, ControllerPublicKey: responseKey.Public().(ed25519.PublicKey), Runner: runner,
				InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t)})
			if err != nil {
				t.Fatal(err)
			}
			if err := agent.acquire(t.Context()); err != nil {
				t.Fatal(err)
			}
			watchdogTicks := make(chan time.Time, 1)
			agent.watchdogTicks = watchdogTicks
			runner.mu.Lock()
			runner.observed["terrabase"] = Observation{Role: "terrabase", Running: true}
			runner.mu.Unlock()
			stopController()
			select {
			case <-controllerDone:
			case <-time.After(2 * time.Second):
				t.Fatal("controller did not stop")
			}
			subject, err := protocol.AgentObservationSubject("gru", testNATSUserKey("node-a"), "session")
			if err != nil {
				t.Fatal(err)
			}
			blocked := make(chan struct{}, 1)
			subscription, err := conn.Subscribe(subject, func(*nats.Msg) {
				select {
				case blocked <- struct{}{}:
				default:
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			defer subscription.Unsubscribe()
			if err := conn.Flush(); err != nil {
				t.Fatal(err)
			}
			monitorCtx, cancel := context.WithCancel(t.Context())
			lost := make(chan error, 1)
			monitorDone := make(chan struct{})
			go func() { agent.maintainSession(monitorCtx, cancel, lost); close(monitorDone) }()
			select {
			case <-blocked:
			case <-time.After(2 * time.Second):
				t.Fatal("renewal did not enter the blocked exchange")
			}
			badClock.Store(true)
			// A single dispatched watchdog tick must fence the blocked renewal.
			watchdogTicks <- time.Now()
			select {
			case <-runner.entered:
			case <-time.After(500 * time.Millisecond):
				t.Fatal("watchdog did not close role during blocked renewal")
			}
			if concurrentFailure {
				conn.Close()
			}
			release()
			select {
			case err := <-lost:
				if err == nil {
					t.Fatal("clock loss did not fail session")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("clock loss did not report failed session")
			}
			select {
			case <-monitorDone:
			case <-time.After(2 * time.Second):
				t.Fatal("session monitor or watchdog goroutine leaked")
			}
			runner.mu.Lock()
			running := runner.observed["terrabase"].Running
			runner.mu.Unlock()
			if runner.closes.Load() != 1 || running || !agent.sessionLost.Load() {
				t.Fatalf("clock fence: closes=%d running=%t lost=%t", runner.closes.Load(), running, agent.sessionLost.Load())
			}
		})
	}
}
