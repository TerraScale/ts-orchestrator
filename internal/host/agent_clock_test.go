//go:build linux

package host

import (
	"context"
	"crypto/ed25519"

	"errors"

	"sync/atomic"
	"testing"
	"time"
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
