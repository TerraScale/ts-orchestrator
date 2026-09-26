package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"strings"
	"sync"
	"time"
	"uuid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/brokerauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Overridden only by tests whose local kernel clock is deliberately not an NTP
// qualification source. Production startup and broker authority share a probe.
var controllerBrokerClockProbe = func() brokerauth.ClockProbe { return brokerauth.KernelClockProbe{} }

func controllerClockCheck(probe brokerauth.ClockProbe) func() error {
	return func() error {
		_, err := brokerauth.MeasureHealthyClock(probe)
		return err
	}
}

func runController(ctx context.Context, cfg Config, output io.Writer) error {
	clockProbe := controllerBrokerClockProbe()
	clockCheck := controllerClockCheck(clockProbe)
	if err := admitControllerBootstrap(ctx, cfg, clockCheck); err != nil {
		return err
	}
	if cfg.NATS.Embedded == nil {
		return errors.New("controller run requires an embedded regional NATS server")
	}
	artifactStoreMaxBytes := cfg.Controller.ArtifactStoreMaxBytes
	if artifactStoreMaxBytes < 0 {
		return errors.New("controller artifact_store_max_bytes must be positive when set")
	}
	if artifactStoreMaxBytes == 0 {
		artifactStoreMaxBytes = delivery.DefaultArtifactStoreMaxBytes
	}
	// Keep room for the configured intent stream, host state, placement KV,
	// and authority log when reserving space for the artifact object store.
	const controlStoreHeadroomBytes int64 = 1536 << 20
	storeLimitBytes := cfg.NATS.Embedded.StoreLimitBytes()
	if storeLimitBytes < artifactStoreMaxBytes || storeLimitBytes-artifactStoreMaxBytes < controlStoreHeadroomBytes {
		return fmt.Errorf("embedded NATS store_max_bytes must leave at least %d bytes for control state beyond artifact_store_max_bytes", controlStoreHeadroomBytes)
	}
	managed, err := loadManagedControllerConfig(cfg)
	if err != nil {
		return err
	}
	if err := validateWorkloadProfiles(cfg.Controller.Workloads); err != nil {
		return err
	}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return err
	}
	responseKey, err := readPrivateKey(cfg.Controller.ResponseKeyFile)
	if err != nil {
		return fmt.Errorf("controller response key: %w", err)
	}
	ticketPrivate, ticketPublic, err := brokerTicketKeys(cfg)
	if err != nil {
		return err
	}
	if !cfg.NATS.Lab {
		if err := clockCheck(); err != nil {
			return fmt.Errorf("production broker NTP clock health: %w", err)
		}
	} else {
		clockCheck = nil
		clockProbe = nil
	}
	cfg.NATS.ClientRole = "controller"
	runtime, err := natscell.Start(ctx, cfg.NATS)
	if err != nil {
		return err
	}
	defer runtime.Close()
	fullClusterReady := func() bool { return runtime.FullClusterReady(cfg.NATS.Replicas) }
	_, _, err = retryControllerOpen(ctx, "wait for regional NATS cluster", fullClusterReady, false,
		func(attempt context.Context) (struct{}, error) {
			return struct{}{}, runtime.WaitForCluster(attempt, cfg.NATS.Replicas)
		}, nil)
	if err != nil {
		return err
	}
	candidateID := cfg.Controller.CandidateID
	if candidateID == "" {
		candidateID = cfg.NATS.Instance
	}
	candidateID = strings.TrimSuffix(candidateID[:min(len(candidateID), 48)], "-") + "-" + uuid.New().String()[:8]
	control, stopAuthority, err := retryControllerOpen(ctx, "start regional authority", fullClusterReady, true,
		func(attempt context.Context) (*authority.Runtime, error) {
			return authority.Start(attempt, runtime.JetStream(), authority.Config{
				Scope: cfg.NATS.Cell, CandidateID: candidateID,
				LeaseDuration: time.Duration(cfg.Controller.LeaseSeconds) * time.Second,
				RenewInterval: time.Duration(cfg.Controller.RenewSeconds) * time.Second,
				Replicas:      cfg.NATS.Replicas,
				ClockCheck:    clockCheck,
			})
		}, func(control *authority.Runtime) { _ = control.Close() })
	if err != nil {
		return err
	}
	defer stopAuthority()
	defer control.Close()
	gate, err := startBrokerGate(ctx, cfg, runtime, control, candidateID, ticketPrivate, ticketPublic, clockProbe)
	if err != nil {
		return fmt.Errorf("start broker admission gate: %w", err)
	}
	planner := &regionalDeliveryPlanner{profiles: cfg.Controller.Workloads}
	service, _, err := retryControllerOpen(ctx, "open regional delivery stores", fullClusterReady, false,
		func(attempt context.Context) (*delivery.Service, error) {
			return delivery.Open(attempt, delivery.Config{
				Conn: runtime.Conn(), JS: runtime.JetStream(), Cell: cfg.NATS.Cell, Replicas: cfg.NATS.Replicas,
				ArtifactStoreMaxBytes: artifactStoreMaxBytes,
				Verifier:              policy.codec, ArtifactVerifier: policy.codec,
				Authorize: policy.authorizeIntent, AuthorizeArtifact: policy.authorizeArtifact,
				Fencer: control, Planner: planner, Writer: planner,
			})
		}, nil)
	if err != nil {
		return err
	}
	var managedController *placement.Controller
	var registrationVerifier host.ManagedRegistrationVerifier
	var placementStore placement.Store
	var fleet oci.Fleet
	if managed != nil {
		journal, _, err := retryControllerOpen(ctx, "open OCI mutation journal", fullClusterReady, false,
			func(attempt context.Context) (*oci.KVJournal, error) {
				return oci.OpenJournal(attempt, runtime.JetStream(), cfg.NATS.Replicas)
			}, nil)
		if err != nil {
			return err
		}
		fleet, err = oci.NewInstancePrincipalFleet(managed.region, managed.intent, journal, control, nil, nil)
		if err != nil {
			return fmt.Errorf("start region-bound OCI fleet: %w", err)
		}
		placementStore, _, err = retryControllerOpen(ctx, "open regional placement state", fullClusterReady, false,
			func(attempt context.Context) (placement.Store, error) {
				return placement.NewJetStreamStore(attempt, runtime.JetStream(), cfg.NATS.Cell, cfg.NATS.Replicas,
					admittedPlacementReader{cell: cfg.NATS.Cell, store: control})
			}, nil)
		if err != nil {
			return err
		}
		registrationVerifier, err = newManagedRegistrationVerifier(
			cfg.NATS.Cell, managed.region.Region, managed.region.Owner, managed.region.Generation,
			control, placementStore, fleet,
		)
		if err != nil {
			return fmt.Errorf("configure managed host enrollment: %w", err)
		}
	}
	hostController, _, err := retryControllerOpen(ctx, "open regional host control", fullClusterReady, false,
		func(attempt context.Context) (*host.Controller, error) {
			return host.NewController(attempt, host.ControllerConfig{
				Cell: cfg.NATS.Cell, Conn: runtime.Conn(), JS: runtime.JetStream(), Artifacts: service.Artifacts(),
				StateReplicas: cfg.NATS.Replicas, ResponseKey: responseKey, HostMutations: control,
				AuthorityEpoch: func() uint64 { return control.Current().Epoch }, AuthorityGuard: control.Guard,
				ManagedRegistrationVerifier: registrationVerifier,
			})
		}, nil)
	if err != nil {
		return err
	}
	planner.hosts = hostController
	if managed != nil {
		managedController, err = placement.StartController(ctx, managed.placementConfig(cfg.NATS.Cell,
			func(err error) { log.Printf("TerraBase placement reconciliation: %v", err) },
			func(reason string) { log.Printf("TerraBase placement held: %s", reason) }),
			placementStore, control, fleet, hostController)
		if err != nil {
			return fmt.Errorf("start regional TerraBase placement: %w", err)
		}
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	artifactSub, err := serveArtifactAdmission(runCtx, runtime.Conn(), cfg.NATS.Cell, control, service)
	if err != nil {
		return fmt.Errorf("serve artifact admission: %w", err)
	}
	defer artifactSub.Unsubscribe()
	enrollmentSub, err := serveHostEnrollment(runCtx, runtime.Conn(), cfg.NATS.Cell, policy, control, hostController)
	if err != nil {
		return fmt.Errorf("serve host enrollment: %w", err)
	}
	defer enrollmentSub.Unsubscribe()
	placementSub, err := servePlacementAdmission(runCtx, runtime.Conn(), cfg.NATS.Cell, policy, control)
	if err != nil {
		return fmt.Errorf("serve placement admission: %w", err)
	}
	defer placementSub.Unsubscribe()
	if gate != nil {
		brokerSub, err := serveBrokerClaimAdmission(runCtx, runtime.Conn(), cfg.NATS.Cell, policy, gate)
		if err != nil {
			return fmt.Errorf("serve broker claim admission: %w", err)
		}
		defer brokerSub.Unsubscribe()
	}
	workerErrors := make(chan error, 3)
	var workers sync.WaitGroup
	workers.Go(func() { workerErrors <- hostController.Run(runCtx) })
	workers.Go(func() { workerErrors <- service.Run(runCtx) })
	if managedController != nil {
		workers.Go(func() { workerErrors <- managedController.Run(runCtx) })
	}
	if err := runtime.Conn().FlushTimeout(2 * time.Second); err != nil {
		stop()
		workers.Wait()
		return fmt.Errorf("flush controller subscriptions: %w", err)
	}
	select {
	case <-hostController.Ready():
	case err := <-workerErrors:
		stop()
		workers.Wait()
		return fmt.Errorf("host controller exited before readiness: %w", err)
	case <-ctx.Done():
		stop()
		workers.Wait()
		return ctx.Err()
	}
	fmt.Fprintf(output, "controller %s ready in cell %s via %s\n", cfg.NATS.Instance, cfg.NATS.Cell, runtime.URL())
	select {
	case <-ctx.Done():
		stop()
		workers.Wait()
		return nil
	case err := <-workerErrors:
		stop()
		workers.Wait()
		if err == nil || errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return nil
		}
		return err
	}
}

// retryControllerOpen keeps the embedded broker alive while JetStream forms
// quorum or temporarily loses a metadata leader during resource provisioning.
// A successful long-lived resource keeps its attempt context; callers close it
// after closing the resource. Other resources release that context immediately.
func retryControllerOpen[T any](ctx context.Context, name string, fullClusterReady func() bool, keepContext bool,
	open func(context.Context) (T, error), closeOnTimeout func(T)) (T, context.CancelFunc, error) {
	var zero T
	noSuitableAttempts := 0
	for attemptNumber := 1; ; attemptNumber++ {
		attemptCtx, cancel := context.WithCancel(ctx)
		timer := time.AfterFunc(20*time.Second, cancel)
		resource, err := open(attemptCtx)
		stopped := timer.Stop()
		if err == nil && stopped && attemptCtx.Err() == nil {
			if !keepContext {
				cancel()
			}
			return resource, cancel, nil
		}
		if err == nil {
			if closeOnTimeout != nil {
				closeOnTimeout(resource)
			}
			err = context.DeadlineExceeded
		}
		timedOut := !stopped || attemptCtx.Err() != nil
		cancel()
		if ctx.Err() != nil {
			return zero, nil, ctx.Err()
		}
		var apiErr *jetstream.APIError
		noSuitable := errors.As(err, &apiErr) && apiErr.ErrorCode == 10005
		if noSuitable {
			noSuitableAttempts++
		}
		// This API error can also mean a permanent storage or placement limit.
		// Allow brief metadata convergence, then surface it for an operator.
		if !transientControllerBootstrapError(err) && !(timedOut && errors.Is(err, context.Canceled)) ||
			noSuitable && noSuitableAttempts >= 10 && fullClusterReady() {
			return zero, nil, fmt.Errorf("%s: %w", name, err)
		}
		log.Printf("%s: %v; retrying with embedded NATS running", name, err)
		backoff := min(time.Duration(attemptNumber)*250*time.Millisecond, 2*time.Second)
		backoff += time.Duration(rand.IntN(250)) * time.Millisecond
		select {
		case <-ctx.Done():
			return zero, nil, ctx.Err()
		case <-time.After(backoff):
		}
	}
}

func transientControllerBootstrapError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) ||
		errors.Is(err, nats.ErrNoResponders) || errors.Is(err, nats.ErrDisconnected) {
		return true
	}
	var apiErr *jetstream.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.ErrorCode == 10005 || apiErr.Code >= 500 &&
		!errors.Is(err, jetstream.ErrJetStreamNotEnabled) &&
		!errors.Is(err, jetstream.ErrJetStreamNotEnabledForAccount)
}
