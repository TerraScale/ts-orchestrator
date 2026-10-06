package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership/clusterhealth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
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
	return acceptedControllerInstallPresent(bootstrapstart.NewMarkerStore().Read)
}

// controllerAdmission is the full restart-admission gate. In the default mode
// it has already passed when runController sees it. In offline-first mode it
// runs in the background after local admission, and wait blocks every
// authority, broker-gate, founder, and mutation path until it passes.
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
// for route formation: only a production restart (accepted marker present)
// whose signed config explicitly opts in. Initial admission never does.
func offlineRestartAdmission(cfg Config) (bool, error) {
	if cfg.NATS.Lab || !cfg.Controller.OfflineRestartAdmission {
		return false, nil
	}
	present, err := controllerBakedInputsPresent()
	if err != nil {
		return false, fmt.Errorf("inspect baked controller bootstrap inputs: %w", err)
	}
	if !present {
		return false, nil
	}
	return controllerMarkerPresent()
}

// startControllerAdmission runs restart admission. By default it is a
// synchronous gate before NATS starts, exactly as before. With
// offline_restart_admission it first passes the local, OCI-free subset, then
// repeats full admission in the background with backoff; the same checks
// still gate everything except broker route formation.
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
	loadedWire, err := cfg.signedWire()
	if err != nil || len(loadedWire) == 0 || len(loadedWire) > maxConfigBytes {
		return errors.New("loaded controller config is not bounded JSON")
	}
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return fmt.Errorf("load fixed baked controller bootstrap inputs: %w", err)
	}
	// Same cell and mode check as full admission, before routes can form.
	if cfg.NATS.Lab || cfg.NATS.Cell != strings.ToLower(string(baked.Identity.Cell)) {
		return errors.New("controller config does not match baked production cell and mode")
	}
	serviceUID, serviceGID, err := controllerServiceIdentity()
	if err != nil {
		return err
	}
	if os.Geteuid() != int(serviceUID) || os.Getegid() != int(serviceGID) {
		return errors.New("local controller restart admission requires the dedicated service account")
	}
	checker, err := bootstrapstart.NewLiveCredentialChecker(cfg.NATS, serviceUID, serviceGID,
		cfg.Controller.ResponseKeyFile, cfg.Controller.BrokerTicketKeyFile,
		cfg.Controller.HostNATSIssuerSeedFile, cfg.Controller.HostTLSIssuerKeyFile,
		cfg.Controller.HostTLSIssuerCertFile, func() error {
			if _, err := readPrivateKey(cfg.Controller.ResponseKeyFile); err != nil {
				return fmt.Errorf("controller response key: %w", err)
			}
			_, _, err := brokerTicketKeys(cfg)
			return err
		})
	if err != nil {
		return err
	}
	checker.TerraBaseCACertFile = cfg.Controller.TerraBaseCACertFile
	checker.TerraBaseCAKeyFile = cfg.Controller.TerraBaseCAKeyFile
	material, err := bootstrapstart.NewMaterialStore(nil, serviceUID, serviceGID)
	if err != nil {
		return err
	}
	manifest, err := readInstalledControllerFile(controllerConfigDirectory, controllerManifestFilename,
		0, 0, 0o644, bootstrapstart.MaxControllerManifestMetadataBytes)
	if err != nil {
		return fmt.Errorf("read installed signed controller manifest: %w", err)
	}
	gate := bootstrapstart.Gate{
		Roots: baked.Roots, AnchorWire: baked.AnchorWire, Expected: baked.Identity.AnchorExpectation(),
		LoadedControllerConfigSHA256: controllerSHA256(loadedWire),
		Descriptor:                   bootstrapstart.NewIMDSClient(),
		Credentials:                  checker, Material: material, Markers: bootstrapstart.NewMarkerStore(),
		SelfUpdate: selfupdate.NewLayout(selfUpdateRoot(cfg.Controller.SelfUpdateRoot)),
	}
	_, err = gate.AdmitRestartLocal(ctx, manifest)
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
				slog.Warn("founder did not stop within its join bound; continuing shutdown",
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
