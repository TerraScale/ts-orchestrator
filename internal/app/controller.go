package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"time"
	"uuid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/brokerauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership/clusterhealth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/sdnotify"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Overridden only by tests whose local kernel clock is deliberately not an NTP
// qualification source. Production startup and broker authority share a probe.
var controllerBrokerClockProbe = func() brokerauth.ClockProbe { return brokerauth.KernelClockProbe{} }

var controllerFounderProduction = runAdmittedControllerFounder

func runAdmittedControllerFounder(ctx context.Context) error {
	// The admission child is a process boundary. Reread the trusted public
	// inputs and accepted marker in this process before any founder work.
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return fmt.Errorf("reread baked controller founder inputs: %w", err)
	}
	accepted, err := bootstrapstart.NewMarkerStore().Read()
	if err != nil {
		return fmt.Errorf("reread accepted controller founder install: %w", err)
	}
	serviceUID, serviceGID, err := controllerServiceIdentity()
	if err != nil {
		return err
	}
	return bootstrapstart.RunAdmittedFounder(ctx, baked, accepted, serviceUID, serviceGID)
}

func controllerClockCheck(probe brokerauth.ClockProbe) func() error {
	return func() error {
		_, err := brokerauth.MeasureHealthyClock(probe)
		return err
	}
}

func runController(ctx context.Context, cfg Config, output io.Writer) (err error) {
	// Take the systemd notification socket before any child process starts.
	notifier := sdnotify.FromEnvironment()
	defer func() { _ = notifier.Stopping() }()
	telemetry, err := startRuntimeObservability(ctx, cfg, "controller", cfg.NATS.Instance)
	if err != nil {
		return fmt.Errorf("start controller observability: %w", err)
	}
	defer telemetry.close()
	clockProbe := controllerBrokerClockProbe()
	clockCheck := controllerClockCheck(clockProbe)
	admission, err := startControllerAdmission(ctx, cfg, clockCheck)
	if err != nil {
		return err
	}
	defer admission.stop()
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
	// A managed TerraBase controller needs no generic delivery profile.
	if managed == nil && len(cfg.Controller.Workloads) == 0 {
		return errors.New("controller requires a managed placement config or explicit workload profiles")
	}
	if err := validateWorkloadProfiles(cfg.Controller.Workloads); err != nil {
		return err
	}
	if err := validateAutoscaleConfig(cfg.Controller.Autoscale, cfg.Controller.Workloads); err != nil {
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
		// Offline-first restarts form routes without NTP; raft needs no wall
		// clock. The same check then gates authority below.
		if !admission.offline {
			if err := clockCheck(); err != nil {
				return fmt.Errorf("production broker NTP clock health: %w", err)
			}
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
	healthCtx, stopHealth := context.WithCancel(ctx)
	var healthReporter clusterhealth.Reporter
	if !cfg.NATS.Lab {
		// Local operator tools (break-glass refound) read the running
		// controller's cluster view from its state directory.
		healthReporter = &clusterhealth.StatusFile{Path: membership.DefaultClusterHealthFile,
			Logger: slog.Default().With("component", "membership")}
	}
	_, brokerStopped, waitHealth := startClusterHealth(healthCtx, runtime, healthReporter)
	defer waitHealth()
	defer stopHealth()
	// Every later startup step runs under the broker's lifetime: a broker
	// that dies while an authority, delivery or placement open is retrying
	// cancels that open, and the controller exits with
	// ErrEmbeddedServerStopped so the service manager restarts it.
	parentCtx := ctx
	ctx, stopBrokerLifetime := brokerLifetimeContext(parentCtx, brokerStopped)
	defer stopBrokerLifetime()
	defer func() {
		if brokerLifetimeEnded(parentCtx, ctx) {
			err = natscell.ErrEmbeddedServerStopped
		}
	}()
	defer stepDownMetaLeaderOnShutdown(runtime, cfg.NATS.Embedded.MembershipCredentialsFile)
	fullClusterReady := func() bool { return runtime.FullClusterReady(cfg.NATS.Replicas) }
	waitCluster := func(waitCtx context.Context) error {
		_, _, err := retryControllerOpen(waitCtx, "wait for regional NATS cluster", fullClusterReady, false,
			func(attempt context.Context) (struct{}, error) {
				return struct{}{}, runtime.WaitForCluster(attempt, cfg.NATS.Replicas)
			}, nil)
		return err
	}
	var foundPeers func(context.Context) error
	if !cfg.NATS.Lab {
		// The founder makes OCI effects, so it waits for full admission.
		foundPeers = func(founderCtx context.Context) error {
			if err := admission.wait(founderCtx); err != nil {
				return err
			}
			return controllerFounderProduction(founderCtx)
		}
	}
	_, stopFounder, err := superviseFounderAndWaitCluster(ctx, waitCluster, foundPeers)
	if err != nil {
		return err
	}
	defer stopFounder()
	if admission.offline {
		slog.Info("controller joined the regional NATS quorum; holding authority until full restart admission passes",
			observability.ComponentKey, "controller", "instance", cfg.NATS.Instance)
		// Full admission may retry for a long time; a dead broker must still
		// end the process so the service manager restarts it. The broker
		// already serves routes and quorum, so keep extending the unit's
		// start timeout while admission rides out an OCI outage; authority
		// and READY still wait for full admission.
		stopExtending := notifier.KeepStarting(ctx, time.Minute, 5*time.Minute)
		select {
		case <-admission.done:
		case <-brokerStopped:
			stopExtending()
			return natscell.ErrEmbeddedServerStopped
		case <-ctx.Done():
			stopExtending()
			return ctx.Err()
		}
		stopExtending()
		if err := clockCheck(); err != nil {
			return fmt.Errorf("production broker NTP clock health: %w", err)
		}
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
	membershipSupervisor, err := startControllerMembership(ctx, cfg, runtime, control)
	if err != nil {
		return fmt.Errorf("start controller membership supervision: %w", err)
	}
	global, err := startGlobalControl(ctx, cfg, runtime.JetStream(), candidateID, clockCheck, fullClusterReady)
	if err != nil {
		return fmt.Errorf("start global control: %w", err)
	}
	defer global.close()
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
	stopCapacity, err := startControllerStorageCapacity(ctx, cfg, runtime, fullClusterReady)
	if err != nil {
		return fmt.Errorf("start storage capacity collector: %w", err)
	}
	defer stopCapacity()
	var managedController *placement.Controller
	var registrationVerifier host.ManagedRegistrationVerifier
	var materialProvider host.ManagedMaterialProvider
	var credentialFloor func(context.Context, host.Registration) (uint64, error)
	var placementStore placement.Store
	var fleet oci.Fleet
	var volumeInspector host.ManagedVolumeInspector
	var terminalExecutor oci.TerminalExecutor
	var materialService *managedmaterial.PreparationService
	var backupRuntime *backupOperationRuntime
	var materialAdmission placementMaterialAdmission
	var ociReconcile *ociReconcileRuntime
	managedRuntimeVerifier := managedRuntimeTargetVerifier(func(ctx context.Context, desired host.Desired,
		registration host.Registration,
	) (bool, error) {
		if managedController == nil {
			return false, errors.New("managed runtime target verifier is not ready")
		}
		return managedController.VerifyManagedRuntimeTarget(ctx, desired, registration)
	})
	if managed != nil {
		if !cfg.NATS.Lab {
			accepted, err := loadAcceptedMaterialConfig(cfg.NATS.Cell, managed.region)
			if err != nil {
				return fmt.Errorf("admit signed managed material domain: %w", err)
			}
			repository, err := managedmaterial.NewOCIRepository(accepted.repository, control)
			if err != nil {
				return fmt.Errorf("open managed material repository: %w", err)
			}
			materialService = &managedmaterial.PreparationService{Cell: cfg.NATS.Cell,
				Repository: repository, Receipts: control, Fencer: control,
				ControllerKey: responseKey, RecipientSigner: accepted.recipientSigner,
				AllowedSubnetCIDR:    accepted.subnetCIDR,
				NativeValidator:      managedmaterial.PackagedNativeMaterialValidator{},
				NativeVerifierSHA256: accepted.nativeVerifierSHA256}
			materialAdmission = preparedMaterialAdmission(*materialService)
		}
		journal, _, err := retryControllerOpen(ctx, "open OCI mutation journal", fullClusterReady, false,
			func(attempt context.Context) (*oci.KVJournal, error) {
				return oci.OpenJournal(attempt, runtime.JetStream(), cfg.NATS.Replicas)
			}, nil)
		if err != nil {
			return err
		}
		launchMaterial, err := bootstrapstart.LoadLaunchMaterial()
		if err != nil {
			return fmt.Errorf("load host launch material: %w", err)
		}
		fleet, err = openManagedControllerFleet(ctx, managed.region, managed.intent, journal, control,
			launchMaterial.HostMetadata(), managedImageVerifierFor(cfg.Controller),
			oci.InstancePrincipalFleetFactory(time.Duration(cfg.Controller.OciObserveVerifyCacheSeconds)*time.Second))
		if err != nil {
			return fmt.Errorf("start region-bound OCI fleet: %w", err)
		}
		inspector, ok := fleet.(oci.VolumeInitializationInspector)
		if !ok {
			return errors.New("managed OCI fleet lacks exact volume initialization inspection")
		}
		volumeInspector = func(ctx context.Context, desired host.Desired, registration host.Registration) (host.VolumeInitObservation, error) {
			if err := verifyCurrentVolumeInitSeat(ctx, placementStore, desired, registration,
				managedRuntimeVerifier); err != nil {
				return host.VolumeInitObservation{}, err
			}
			launch := *desired.ManagedMember
			proof, err := inspector.InspectVolumeInitialization(ctx, oci.VolumeInitializationPins{
				DatabaseID:  registration.ManagedPlacement.DatabaseID,
				PartitionID: registration.ManagedPlacement.PartitionID,
				InstanceID:  launch.OCI.InstanceID, HostCreateKey: launch.OCI.CreateKey,
				VolumeID: launch.VolumeID, AttachmentID: launch.AttachmentID,
				AttachmentETag: launch.AttachmentETag, Device: launch.Runtime.DevicePath,
				FileSystemUUID: launch.Runtime.FileSystemUUID, FileSystemType: launch.Runtime.FileSystemType,
			})
			if err != nil {
				return host.VolumeInitObservation{}, err
			}
			if err := verifyCurrentVolumeInitSeat(ctx, placementStore, desired, registration,
				managedRuntimeVerifier); err != nil {
				return host.VolumeInitObservation{}, err
			}
			return host.VolumeInitObservation{BootDescriptorSHA256: proof.BootDescriptorSHA256,
				AllowFormat: proof.AllowFormat}, nil
		}
		terminalExecutor, ok = fleet.(oci.TerminalExecutor)
		if !ok {
			return errors.New("managed OCI fleet lacks exact terminal reconciliation")
		}
		placementStore, _, err = retryControllerOpen(ctx, "open regional placement state", fullClusterReady, false,
			func(attempt context.Context) (placement.Store, error) {
				return placement.NewJetStreamStore(attempt, runtime.JetStream(), cfg.NATS.Cell, cfg.NATS.Replicas,
					admittedPlacementReader{cell: cfg.NATS.Cell, store: control, material: materialAdmission})
			}, nil)
		if err != nil {
			return err
		}
		stopBackups, err := startVolumeBackups(ctx, cfg, managed, control, placementStore)
		if err != nil {
			return fmt.Errorf("start volume backup policy: %w", err)
		}
		defer stopBackups()
		if reconcile := cfg.Controller.OciReconcile; reconcile != nil && reconcile.Enabled {
			ociReconcile, _, err = retryControllerOpen(ctx, "open OCI resource reconcile state", fullClusterReady, false,
				func(attempt context.Context) (*ociReconcileRuntime, error) {
					return newOCIReconcileRunner(attempt, *reconcile, managed.region, runtime.JetStream(),
						cfg.NATS.Replicas, control, fleet)
				}, nil)
			if err != nil {
				return err
			}
		}
		registrationVerifier, err = newManagedRegistrationVerifier(
			cfg.NATS.Cell, managed.region.Region, managed.region.Owner, managed.region.Generation,
			control, placementStore, fleet,
		)
		if err != nil {
			return fmt.Errorf("configure managed host enrollment: %w", err)
		}
		if materialService != nil {
			credentials := managedmaterial.CredentialService{Preparation: *materialService, Store: control}
			materialProvider = admittedManagedMaterialProvider(*materialService, control, placementStore, credentials,
				managedRuntimeVerifier)
			credentialFloor = func(ctx context.Context, registration host.Registration) (uint64, error) {
				if registration.ManagedPlacement == nil {
					return 1, nil
				}
				state, _, err := credentials.Current(ctx, registration.ManagedPlacement.DatabaseID,
					registration.ManagedPlacement.PartitionID)
				return state.Generation, err
			}
		}
	}
	var managedDesiredVerifier host.ManagedDesiredVerifier
	if managed != nil {
		managedDesiredVerifier = func(verifyCtx context.Context, desired host.Desired,
			registration host.Registration, current host.Desired, currentExists bool,
		) error {
			if managedController == nil {
				return errors.New("managed placement desired verifier is not ready")
			}
			return managedController.VerifyManagedDesired(verifyCtx, desired, registration, current, currentExists)
		}
	}
	hostController, _, err := retryControllerOpen(ctx, "open regional host control", fullClusterReady, false,
		func(attempt context.Context) (*host.Controller, error) {
			return host.NewController(attempt, host.ControllerConfig{
				Cell: cfg.NATS.Cell, Conn: runtime.Conn(), JS: runtime.JetStream(), Artifacts: service.Artifacts(),
				StateReplicas: cfg.NATS.Replicas, ResponseKey: responseKey, HostMutations: control,
				AuthorityEpoch: func() uint64 { return control.Current().Epoch }, AuthorityGuard: control.Guard,
				AuthorityLeader:             func() bool { return control.Current().Leader },
				ManagedRegistrationVerifier: registrationVerifier,
				ManagedDesiredVerifier:      managedDesiredVerifier,
				ManagedMaterialProvider:     materialProvider,
				ManagedCredentialFloor:      credentialFloor,
				ManagedVolumeInspector:      volumeInspector,
			})
		}, nil)
	if err != nil {
		return err
	}
	planner.hosts = hostController
	workloadReconciler, capacityScaler, err := startWorkloadAutoscale(cfg.NATS.Cell, cfg.Controller.Autoscale,
		cfg.Controller.Workloads, hostController, control)
	if err != nil {
		return err
	}
	planner.workloads = workloadReconciler
	if materialService != nil && managed != nil {
		backupRuntime = &backupOperationRuntime{cell: cfg.NATS.Cell,
			memberRole: managed.placement.MemberRole, control: control,
			placements: placementStore, hosts: hostController,
			producer: managedmaterial.BackupOperationProducer{
				Preparation: *materialService, Store: control},
			policy: policy, responseKey: responseKey}
	}
	placementHolds := new(placementHoldLog)
	holdDecisions := newHoldJournal(cfg.NATS.Cell)
	rolloutKnownBadReleases := newRolloutKnownBad(cfg)
	if managed != nil {
		managedController, err = placement.StartController(ctx, withKnownBad(managed.placementConfig(cfg.NATS.Cell,
			func(err error) {
				changed := placementHolds.recordChange("reconciliation error: " + err.Error())
				slog.Warn("TerraBase placement reconciliation failed", observability.ComponentKey, "placement",
					"error", err, "repeated", !changed)
			},
			func(reason string) {
				changed := placementHolds.recordChange(reason)
				slog.Info("TerraBase placement held", observability.ComponentKey, "placement",
					"reason", reason, observability.EventKey, changed)
				holdDecisions.record(ctx, reason, time.Now())
			}), rolloutKnownBadReleases),
			placement.JournaledStore(placementStore, cfg.NATS.Cell), control, fleet, hostController, hostController,
			func(ctx context.Context, digest, role, environment string) (placement.AdmittedArtifact, error) {
				record, err := service.ResolveAdmittedArtifact(ctx, digest, role, environment)
				if err != nil {
					return placement.AdmittedArtifact{}, err
				}
				return placement.AdmittedArtifact{
					Digest: record.Digest, ManifestDigest: record.ManifestDigest,
					SourceDigest: record.Source.TreeDigest,
				}, nil
			})
		if err != nil {
			return fmt.Errorf("start regional TerraBase placement: %w", err)
		}
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	var enrollmentErrors <-chan error
	var managedEnrollment *managedHostEnrollment
	if managed != nil && !cfg.NATS.Lab {
		server, listener, serveErrors, err := startManagedHostEnrollment(runCtx, cfg, runtime,
			managed, fleet, control, placementStore, hostController, registrationVerifier, responseKey, control)
		if err != nil {
			return fmt.Errorf("start private managed host enrollment: %w", err)
		}
		var ok bool
		managedEnrollment, ok = server.Handler.(*managedHostEnrollment)
		if !ok {
			return errors.New("private managed host enrollment handler is unavailable")
		}
		stopEnrollment := context.AfterFunc(runCtx, func() { _ = server.Close() })
		defer stopEnrollment()
		defer server.Close()
		defer listener.Close()
		enrollmentErrors = serveErrors
	}
	var terminalRuntime *managedTerminalRuntime
	if managed != nil {
		terminalRuntime = &managedTerminalRuntime{
			control: control, placements: placementStore, hosts: hostController,
			executor: terminalExecutor, enrollment: managedEnrollment,
			requireEnrollment: !cfg.NATS.Lab,
		}
	}
	artifactSub, err := serveArtifactAdmission(runCtx, runtime.Conn(), cfg.NATS.Cell, control, service)
	if err != nil {
		return fmt.Errorf("serve artifact admission: %w", err)
	}
	defer artifactSub.Unsubscribe()
	enrollmentSub, err := serveHostEnrollment(runCtx, runtime.Conn(), cfg.NATS.Cell, policy, control, hostController, managedEnrollment)
	if err != nil {
		return fmt.Errorf("serve host enrollment: %w", err)
	}
	defer enrollmentSub.Unsubscribe()
	placementVerifiers := []placementMaterialAdmission{}
	if materialService != nil {
		placementVerifiers = append(placementVerifiers, materialAdmission)
	}
	placementSub, err := servePlacementAdmission(runCtx, runtime.Conn(), cfg.NATS.Cell, policy, control, placementVerifiers...)
	if err != nil {
		return fmt.Errorf("serve placement admission: %w", err)
	}
	defer placementSub.Unsubscribe()
	if managed != nil {
		statusSub, err := servePlacementStatus(runCtx, runtime.Conn(), placementStatusSource{cell: cfg.NATS.Cell,
			policy: policy, control: control, placements: placementStore, hosts: hostController,
			holds: placementHolds, responseKey: responseKey,
			owner: managed.region.Owner, fleetGeneration: managed.region.Generation})
		if err != nil {
			return fmt.Errorf("serve TerraBase placement status: %w", err)
		}
		defer statusSub.Unsubscribe()
		managedUpdateSub, err := serveManagedUpdateAdmission(runCtx, runtime.Conn(), cfg.NATS.Cell,
			policy, control, managedController, service)
		if err != nil {
			return fmt.Errorf("serve managed TerraBase update admission: %w", err)
		}
		defer managedUpdateSub.Unsubscribe()
	}
	if managed != nil {
		terminalEnrollment := func() (*managedHostEnrollment, error) {
			if managedEnrollment == nil || managedEnrollment.grants == nil {
				return nil, errors.New("managed terminal admission requires the enrollment grant store")
			}
			return managedEnrollment, nil
		}
		grantFence := func(ctx context.Context, epoch uint64, intent authority.TerminalIntent) error {
			enrollment, err := terminalEnrollment()
			if err != nil {
				return err
			}
			return enrollment.fenceTerminalGrants(ctx, epoch, intent)
		}
		grantProof := func(ctx context.Context, intent authority.TerminalIntent) error {
			enrollment, err := terminalEnrollment()
			if err != nil {
				return err
			}
			return enrollment.verifyTerminalGrantFence(ctx, intent)
		}
		grantStatus := func(ctx context.Context, intent authority.TerminalIntent) error {
			enrollment, err := terminalEnrollment()
			if err != nil {
				return err
			}
			return enrollment.verifyTerminalGrants(ctx, intent)
		}
		terminalAdmissionSub, err := serveTerminalAdmission(runCtx, runtime.Conn(), cfg.NATS.Cell,
			policy, control, managed.region, placementStore, terminalExecutor, grantFence, grantProof, grantStatus)
		if err != nil {
			return fmt.Errorf("serve managed terminal admission: %w", err)
		}
		defer terminalAdmissionSub.Unsubscribe()
	}
	if materialService != nil {
		backupSub, err := serveBackupOperation(runCtx, runtime.Conn(), *backupRuntime)
		if err != nil {
			return fmt.Errorf("serve backup operation admission: %w", err)
		}
		defer backupSub.Unsubscribe()
		materialSub, err := serveMaterialPreparation(runCtx, runtime.Conn(), cfg.NATS.Cell, policy, *materialService)
		if err != nil {
			return fmt.Errorf("serve managed material preparation: %w", err)
		}
		defer materialSub.Unsubscribe()
		credentialsSub, err := serveMaterialCredentials(runCtx, runtime.Conn(), cfg.NATS.Cell,
			policy, managedmaterial.CredentialService{Preparation: *materialService, Store: control})
		if err != nil {
			return fmt.Errorf("serve managed client credentials: %w", err)
		}
		defer credentialsSub.Unsubscribe()
		credentialStatusSub, err := serveMaterialCredentialStatus(runCtx, runtime.Conn(), cfg.NATS.Cell,
			policy, managedmaterial.CredentialService{Preparation: *materialService, Store: control}, hostController)
		if err != nil {
			return fmt.Errorf("serve managed client credential status: %w", err)
		}
		defer credentialStatusSub.Unsubscribe()
	}
	if gate != nil {
		brokerSub, err := serveBrokerClaimAdmission(runCtx, runtime.Conn(), cfg.NATS.Cell, policy, gate)
		if err != nil {
			return fmt.Errorf("serve broker claim admission: %w", err)
		}
		defer brokerSub.Unsubscribe()
	}
	// Optional rollout and region planner providers, behind their flags.
	rollouts, err := startRollouts(runCtx, cfg, runtime.JetStream(), control, fullClusterReady, rolloutKnownBadReleases)
	if err != nil {
		return fmt.Errorf("start rollout store: %w", err)
	}
	budgets, err := startRegionPlanner(runCtx, cfg, runtime.JetStream(), global, placementHolds, fullClusterReady)
	if err != nil {
		return fmt.Errorf("start region planner: %w", err)
	}
	// runController refused a configuration without an embedded broker at
	// its top, so Embedded is always set here.
	if err := telemetry.attachController(runCtx, controllerObservation{nats: runtime, replicas: cfg.NATS.Replicas,
		brokerIDs: cfg.NATS.Embedded.BrokerIDs, authority: control, placements: placementStore, managed: managed != nil,
		holds: placementHolds, autoscalers: workloadReconciler, linkedPeers: globalMirrorPeers(cfg.NATS),
		rollouts: rollouts, budgets: budgets, ociResources: ociReconcile.resources()},
		[]observability.FilesystemRole{{Role: "nats", Path: cfg.NATS.Embedded.StoreDir}}); err != nil {
		return fmt.Errorf("attach controller observability: %w", err)
	}
	workerErrors := make(chan error, 10)
	var workers sync.WaitGroup
	workers.Go(func() { workerErrors <- hostController.Run(runCtx) })
	workers.Go(func() { workerErrors <- service.Run(runCtx) })
	if backupRuntime != nil {
		workers.Go(func() { workerErrors <- backupRuntime.Run(runCtx) })
	}
	if managedController != nil {
		workers.Go(func() { workerErrors <- managedController.Run(runCtx) })
	}
	if terminalRuntime != nil {
		workers.Go(func() { workerErrors <- terminalRuntime.Run(runCtx) })
	}
	if ociReconcile != nil {
		workers.Go(func() { workerErrors <- ociReconcile.runner.Run(runCtx) })
	}
	if membershipSupervisor != nil {
		workers.Go(func() { workerErrors <- membershipSupervisor.Run(runCtx) })
	}
	if workloadReconciler != nil {
		workers.Go(func() { workerErrors <- workloadReconciler.Run(runCtx) })
	}
	if capacityScaler != nil {
		workers.Go(func() { workerErrors <- capacityScaler.Run(runCtx) })
	}
	if enrollmentErrors != nil {
		workers.Go(func() { workerErrors <- <-enrollmentErrors })
	}
	if !cfg.NATS.Lab {
		workers.Go(func() {
			runNetBirdManagement(runCtx, netbird.PublicConfigPath, func() bool { return control.Current().CanMutate() })
		})
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
	case <-brokerStopped:
		stop()
		workers.Wait()
		return natscell.ErrEmbeddedServerStopped
	case <-ctx.Done():
		stop()
		workers.Wait()
		return ctx.Err()
	}
	telemetry.markStarted()
	slog.Info("controller ready", observability.ComponentKey, "controller", observability.EventKey, true)
	fmt.Fprintf(output, "controller %s ready in cell %s via %s\n", cfg.NATS.Instance, cfg.NATS.Cell, runtime.URL())
	if err := notifier.Ready("controller " + cfg.NATS.Instance + " ready in cell " + cfg.NATS.Cell); err != nil {
		slog.Warn("systemd readiness notification failed", observability.ComponentKey, "controller", "error", err)
	}
	// Watchdog keepalives stop when the embedded broker or its in-process
	// client is no longer usable, so WatchdogSec= restarts a wedged
	// controller instead of leaving a silent Raft peer.
	go notifier.RunWatchdog(runCtx, runtime.Ready)
	emitSelfUpdateProof(cfg.Controller.SelfUpdateProofFile, cfg.Controller.SelfUpdateRoot, cfg.Controller.ResponseKeyFile, controllerUnit, output)
	select {
	case <-parentCtx.Done():
		stop()
		workers.Wait()
		return nil
	case <-brokerStopped:
		stop()
		workers.Wait()
		return natscell.ErrEmbeddedServerStopped
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
		slog.Warn("controller startup step retrying with embedded NATS running",
			observability.ComponentKey, "controller", "step", name, "attempt", attemptNumber, "error", err)
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
	if errors.Is(err, natscell.ErrEmbeddedServerStopped) {
		return false
	}
	if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrLeaseCorrupt) ||
		errors.Is(err, authority.ErrOutcomeUnknown) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) ||
		errors.Is(err, nats.ErrNoResponders) || errors.Is(err, nats.ErrDisconnected) ||
		errors.Is(err, authority.ErrConflict) || errors.Is(err, delivery.ErrStoreNotReady) {
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
