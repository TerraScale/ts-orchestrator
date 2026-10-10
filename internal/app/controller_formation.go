package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership/clusterhealth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// Backoff bounds for the supervised seed founder and for repeated full
// restart admission in offline-first mode. Tests shorten them.
var (
	controllerFounderMinBackoff   = 5 * time.Second
	controllerFounderMaxBackoff   = 5 * time.Minute
	controllerAdmissionMinBackoff = 5 * time.Second
	controllerAdmissionMaxBackoff = 2 * time.Minute
	// controllerFounderJoinTimeout bounds how long shutdown waits for a
	// cancelled founder. With the broker drain, handoff and lame-duck
	// windows it stays well below the unit's TimeoutStopSec=60s.
	controllerFounderJoinTimeout = 20 * time.Second
)

var controllerLocalAdmissionProduction = admitProductionControllerRestartLocal

var controllerMarkerPresent = func() (bool, error) {
	return acceptedControllerInstallPresent(bootstrapstart.NewMarkerStore().ReadIdentity)
}

// controllerAdmission is the full admission gate. Production restarts run it
// in the background after local admission; wait blocks every authority,
// broker-gate, founder, and mutation path until it passes. Initial and lab
// admission finish before runtime starts.
type controllerAdmission struct {
	offline bool
	done    chan struct{}
	cancel  context.CancelFunc
	stopped chan struct{}
}

func (admission *controllerAdmission) wait(ctx context.Context) error {
	select {
	case <-admission.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// stop cancels a pending background admission and joins it, so its child
// process group is killed before the controller returns.
func (admission *controllerAdmission) stop() {
	if admission.cancel != nil {
		admission.cancel()
		<-admission.stopped
	}
}

// offlineRestartAdmission reports whether this start may use local admission
// for route formation: only a production restart with an accepted marker.
// Initial admission never does.
func offlineRestartAdmission(cfg Config) (bool, error) {
	if cfg.NATS.Lab {
		return false, nil
	}
	return controllerMarkerPresent()
}

// startControllerAdmission admits initial and lab starts before NATS starts.
// Accepted production restarts first pass local proof, then repeat full
// admission in the background; it gates everything except route formation.
// An interrupted material install was finished before this process started
// by selfupdate prepare: this process cannot write its credential directory.
func startControllerAdmission(ctx context.Context, cfg Config, clockCheck func() error) (*controllerAdmission, error) {
	offline, err := offlineRestartAdmission(cfg)
	if err != nil {
		return nil, err
	}
	admission := &controllerAdmission{offline: offline, done: make(chan struct{})}
	if !offline {
		if err := admitControllerBootstrap(ctx, cfg, clockCheck); err != nil {
			return nil, err
		}
		close(admission.done)
		return admission, nil
	}
	if err := controllerLocalAdmissionProduction(ctx, cfg); err != nil {
		return nil, fmt.Errorf("offline controller restart admission: %w", err)
	}
	log.Printf("controller %s passed local restart admission; starting broker routes before OCI re-verification", cfg.NATS.Instance)
	runCtx, cancel := context.WithCancel(ctx)
	admission.cancel, admission.stopped = cancel, make(chan struct{})
	go func() {
		defer close(admission.stopped)
		backoff := controllerAdmissionMinBackoff
		for attempt := 1; ; attempt++ {
			err := admitControllerBootstrap(runCtx, cfg, clockCheck)
			if err == nil {
				log.Printf("controller %s passed full restart admission after %d attempt(s)", cfg.NATS.Instance, attempt)
				close(admission.done)
				return
			}
			if runCtx.Err() != nil {
				return
			}
			delay := backoff + time.Duration(rand.Int64N(int64(backoff)/5+1))
			log.Printf("full controller restart admission attempt %d: %v; authority held, broker routes stay up, retrying in %s",
				attempt, err, delay.Round(time.Second))
			backoff = min(backoff*2, controllerAdmissionMaxBackoff)
			select {
			case <-runCtx.Done():
				return
			case <-time.After(delay):
			}
		}
	}()
	return admission, nil
}

// admitProductionControllerRestartLocal runs in the service-account
// controller itself: it makes no OCI SDK call, so it needs no child process.
func admitProductionControllerRestartLocal(ctx context.Context, cfg Config) error {
	gate, _, err := acceptedControllerAdmissionGate(cfg, bootstrapstart.NewMarkerStore(), nil)
	if err != nil {
		return err
	}
	_, err = gate.AdmitRestartLocal(ctx)
	return err
}

// superviseFounderAndWaitCluster starts the seed founder as a supervised
// background worker and waits for the regional NATS quorum. A founder error
// never ends the wait or tears down the broker; only a cluster failure does.
// The returned stop cancels the founder and joins it for at most
// controllerFounderJoinTimeout. The OCI SDK's instance-principal constructors
// and retry sleeps do not observe a context, so an unbounded join could hold
// shutdown past the unit's stop timeout and turn it into a SIGKILL that skips
// broker draining and leadership handoff. A founder still inside such a call
// ends with the process, which every founder effect already tolerates: each
// launch is pinned by its ledger intent and idempotent retry token, exactly as
// for a crash.
func superviseFounderAndWaitCluster(ctx context.Context, waitCluster, foundPeers func(context.Context) error,
) (*bootstrapstart.FounderSupervisor, func(), error) {
	if foundPeers == nil {
		return nil, func() {}, waitCluster(ctx)
	}
	founderCtx, cancel := context.WithCancel(ctx)
	supervisor := &bootstrapstart.FounderSupervisor{Found: foundPeers,
		MinBackoff: controllerFounderMinBackoff, MaxBackoff: controllerFounderMaxBackoff}
	done := make(chan struct{})
	go func() {
		defer close(done)
		supervisor.Supervise(founderCtx)
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			timer := time.NewTimer(controllerFounderJoinTimeout)
			defer timer.Stop()
			select {
			case <-done:
			case <-timer.C:
				slog.WarnContext(ctx, "founder did not stop within its join bound; continuing shutdown",
					observability.ComponentKey, "founder", "bound", controllerFounderJoinTimeout)
			}
		})
	}
	if err := waitCluster(ctx); err != nil {
		stop()
		return nil, func() {}, err
	}
	return supervisor, stop, nil
}

// brokerLifetimeContext derives a context that also ends when brokerStopped
// closes, with ErrEmbeddedServerStopped as its cause. stop releases the
// watcher.
func brokerLifetimeContext(parent context.Context, brokerStopped <-chan struct{},
) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(parent)
	go func() {
		select {
		case <-brokerStopped:
			cancel(natscell.ErrEmbeddedServerStopped)
		case <-ctx.Done():
		}
	}()
	return ctx, func() { cancel(context.Canceled) }
}

// brokerLifetimeEnded reports whether ctx ended because the embedded broker
// stopped while the parent context was still live.
func brokerLifetimeEnded(parent, ctx context.Context) bool {
	return parent.Err() == nil && errors.Is(context.Cause(ctx), natscell.ErrEmbeddedServerStopped)
}

// startClusterHealth supervises the local broker's view of the regional
// cluster until ctx ends. stopped is closed once the embedded broker is seen
// dead, so the controller can exit and let the service manager restart it.
func startClusterHealth(ctx context.Context, runtime *natscell.Runtime, reporter clusterhealth.Reporter,
) (supervisor *clusterhealth.Supervisor, stopped <-chan struct{}, wait func()) {
	brokerStopped := make(chan struct{})
	var once sync.Once
	supervisor = &clusterhealth.Supervisor{
		Observe: func() (clusterhealth.Observation, error) {
			observed, err := runtime.ObserveCluster()
			return clusterHealthObservation(observed), err
		},
		Logger: slog.Default(),
		Reporter: clusterhealth.ReporterFunc(func(status clusterhealth.Status) {
			if status.Phase == clusterhealth.PhaseStopped {
				once.Do(func() { close(brokerStopped) })
			}
			if reporter != nil {
				reporter.ReportClusterHealth(status)
			}
		}),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = supervisor.Run(ctx)
	}()
	return supervisor, brokerStopped, func() { <-done }
}

func clusterHealthObservation(observed natscell.ClusterObservation) clusterhealth.Observation {
	peers := make([]clusterhealth.Peer, 0, len(observed.MetaPeers))
	for _, peer := range observed.MetaPeers {
		peers = append(peers, clusterhealth.Peer{Name: peer.Name, Current: peer.Current, Offline: peer.Offline,
			Active: peer.Active, Lag: peer.Lag})
	}
	return clusterhealth.Observation{ServerName: observed.ServerName, Running: observed.Running,
		Expected: observed.ExpectedPeers, Routes: observed.Routes, MetaLeader: observed.MetaLeader,
		MetaSize: observed.MetaSize, MetaQuorum: observed.MetaQuorum, Peers: peers}
}
