package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/atlas"
	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/membership"
	"github.com/TerraScale/ts-orchestrator/internal/membership/clusterhealth"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutexec"
	"github.com/TerraScale/ts-orchestrator/internal/sdnotify"
	"github.com/TerraScale/ts-orchestrator/internal/seatrollout"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Overridden only by tests whose local kernel clock is deliberately not an NTP
// qualification source. Production startup and broker authority share a probe.
var controllerBrokerClockProbe = func() brokerauth.ClockProbe { return brokerauth.KernelClockProbe{} }

var controllerFounderProduction = runAdmittedControllerFounder
var controllerRuntimeProduction = openControllerRuntime

func runAdmittedControllerFounder(ctx context.Context) error {
	identity, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return err
	}
	if _, err := bootstrapstart.ReadIdentityRekeyJournal(identity); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// The admission child is a process boundary. Reread the trusted public
	// inputs and accepted marker in this process before any founder work.
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return fmt.Errorf("reread baked controller founder inputs: %w", err)
	}
	accepted, err := bootstrapstart.NewMarkerStore().ReadInitialFormation()
	if err != nil {
		return fmt.Errorf("reread accepted controller founder install: %w", err)
	}
	serviceUID, serviceGID, err := controllerServiceIdentity()
	if err != nil {
		return err
	}
	if accepted.DeploymentID != identity.DeploymentID || accepted.Cell != identity.Cell || accepted.Slot != identity.Slot ||
		accepted.InstanceOCID != identity.InstanceOCID || accepted.PrimaryVNICOCID != identity.PrimaryVNICOCID {
		return errors.New("initial formation history differs from accepted installation")
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
	if err := validateWorkloadProfiles(cfg.NATS.Cell, cfg.Controller.Workloads); err != nil {
		return err
	}
	if err := validateAutoscaleConfig(cfg.Controller.Autoscale, cfg.Controller.Workloads); err != nil {
		return err
	}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return err
	}
	memberRole := ""
	if managed != nil {
		memberRole = managed.placement.MemberRole
	}
	services, err := newSpecRegistry(cfg, memberRole)
	if err != nil {
		return err
	}
	if !entityid.Valid(services.identity.DeploymentID) {
		return errors.New("controller authority requires a trusted deployment ID; lab controllers require spec_trust")
	}
	if managed != nil {
		services.ociRegion = &managed.region
	}
	policy.services = services
	// Every handler holds a copy of policy, which shares its signer set: an
	// adopted spec's signers apply to all of them.
	services.replaceSigners = policy.replaceSigners
	// The release channel bridge needs the OCI region (sa-saopaulo-1), not
	// the fleet's region code (GRU).
	region := ""
	if managed != nil {
		if region, err = managed.region.Region.OCIRegion(); err != nil {
			return err
		}
	}
	if policy.rollouts, err = newRolloutControl(cfg, services, region); err != nil {
		return err
	}
	responseKey, err := readPrivateKey(cfg.Controller.ResponseKeyFile)
	if err != nil {
		return fmt.Errorf("controller response key: %w", err)
	}
	var terraBaseCA *terrabase.CA
	if cfg.Controller.TerraBaseCACertFile != "" || cfg.Controller.TerraBaseCAKeyFile != "" {
		if terraBaseCA, err = terrabase.LoadCA(cfg.Controller.TerraBaseCACertFile, cfg.Controller.TerraBaseCAKeyFile); err != nil {
			return err
		}
	}
	ticketPrivate, ticketPublic, err := brokerTicketKeys(cfg)
	if err != nil {
		return err
	}

	// Offline-first restarts form routes without NTP; raft needs no wall
	// clock. The same check then gates authority below.
	if !admission.offline {
		if err := clockCheck(); err != nil {
			return fmt.Errorf("production broker NTP clock health: %w", err)
		}
	}

	cfg.NATS.ClientRole = "controller"
	runtime, err := controllerRuntimeProduction(ctx, cfg, clockCheck)
	if err != nil {
		return err
	}
	defer runtime.Close()
	healthCtx, stopHealth := context.WithCancel(ctx)
	var healthReporter clusterhealth.Reporter

	// Local operator tools (break-glass refound) read the running
	// controller's cluster view from its state directory.
	healthReporter = &clusterhealth.StatusFile{Path: membership.DefaultClusterHealthFile,
		Logger: slog.Default().With("component", "membership")}

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

	// The founder makes OCI effects, so it waits for full admission.
	foundPeers = func(founderCtx context.Context) error {
		if err := admission.wait(founderCtx); err != nil {
			return err
		}
		return controllerFounderProduction(founderCtx)
	}

	_, stopFounder, err := superviseFounderAndWaitCluster(ctx, waitCluster, foundPeers)
	if err != nil {
		return err
	}
	defer stopFounder()
	if admission.offline {
		slog.InfoContext(ctx, "controller joined the regional NATS quorum; holding authority until full restart admission passes",
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
	// Restored configuration must be in place before any store opens.
	if err := restoreControllerKV(ctx, cfg, runtime.JetStream(), fullClusterReady); err != nil {
		return err
	}
	candidateID := entityid.New()
	control, stopAuthority, err := retryControllerOpen(ctx, "start regional authority", fullClusterReady, true,
		func(attempt context.Context) (*authority.Runtime, error) {
			return authority.Start(attempt, runtime.JetStream(), authority.Config{
				Scope: cfg.NATS.Cell, DeploymentID: services.identity.DeploymentID, CandidateID: candidateID,
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
	global, err := startGlobalControl(ctx, cfg, runtime.JetStream(), services.identity.DeploymentID, candidateID, clockCheck, fullClusterReady)
	if err != nil {
		return fmt.Errorf("start global control: %w", err)
	}
	defer global.close()
	peers := &rosterPeers{}
	gate, err := startBrokerGate(ctx, cfg, runtime, control, services.identity.DeploymentID, candidateID, ticketPrivate, ticketPublic, clockProbe)
	if err != nil {
		return fmt.Errorf("start broker admission gate: %w", err)
	}
	planner := &regionalDeliveryPlanner{profiles: services.profiles, address: services.nodeAddress}
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
	nativeKV, _, err := retryControllerOpen(ctx, "open native release history", fullClusterReady, false,
		func(attempt context.Context) (jetstream.KeyValue, error) {
			return openNativeHistory(attempt, runtime.JetStream(), cfg.NATS.Replicas)
		}, nil)
	if err != nil {
		return err
	}
	nativeReleases := &nativeHistory{kv: nativeKV, js: runtime.JetStream(), services: services,
		deliveries: service, fencer: control, cfg: cfg}
	planner.nativeHistory, services.nativeHistory = nativeReleases, nativeReleases
	stopKVSnapshots, kvSnapshots, err := startKVSnapshots(ctx, cfg, runtime.JetStream(), control)
	if err != nil {
		return err
	}
	defer stopKVSnapshots()
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

		journal, _, err := retryControllerOpen(ctx, "open OCI mutation journal", fullClusterReady, false,
			func(attempt context.Context) (*oci.KVJournal, error) {
				return oci.OpenJournal(attempt, runtime.JetStream(), cfg.NATS.Replicas)
			}, nil)
		if err != nil {
			return err
		}
		acceptedLaunch, err := bootstrapstart.NewMarkerStore().ReadIdentity()
		if err != nil {
			return err
		}
		launchMaterial, err := bootstrapstart.LoadAcceptedHostLaunchMaterial(acceptedLaunch)
		if err != nil {
			return fmt.Errorf("load host launch material: %w", err)
		}
		fleet, err = openManagedControllerFleet(ctx, managed.region, managed.intent, journal, control,
			launchMaterial.HostMetadata(), managedImageVerifierFor(cfg.Controller, services.hostImageSnapshot, services.holdLaunch),
			oci.NewInstancePrincipalFleetWithImageVerifier)
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
		stopBackups, err := startVolumeBackups(ctx, managed, control, placementStore, journal)
		if err != nil {
			return fmt.Errorf("start volume backup policy: %w", err)
		}
		defer stopBackups()
		if reconcile := cfg.Controller.OciReconcile; reconcile != nil && reconcile.Enabled {
			ociReconcile, _, err = retryControllerOpen(ctx, "open OCI resource reconcile state", fullClusterReady, false,
				func(attempt context.Context) (*ociReconcileRuntime, error) {
					return newOCIReconcileRunner(attempt, *reconcile, managed.region, runtime.JetStream(),
						cfg.NATS.Replicas, control, fleet, services.profiles, services.ociDesired)
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
	// TerraBase seat rollouts hold a static member's restart until its seat
	// is permitted, so the host controller needs the seat records first.
	var seatStore *seatrollout.Store
	var restartGate func(context.Context, string, host.Desired) (bool, error)
	if seats := cfg.Controller.TerraBaseSeats; seats != nil && seats.Enabled {
		if _, _, err := seats.durations(); err != nil {
			return err
		}
		if seatStore, _, err = retryControllerOpen(ctx, "open TerraBase seat records", fullClusterReady, false,
			func(attempt context.Context) (*seatrollout.Store, error) {
				return seatrollout.Open(attempt, runtime.JetStream(), cfg.NATS.Replicas, control)
			}, nil); err != nil {
			return err
		}
		restartGate = seatStore.Granted
		policy.rollouts.drainedSeats = seatStore.Drained
	}
	// Service releases sequenced by a release fence (TS-610) hold a host's
	// restart until the leader permits its node, on every controller.
	var releaseChannel jetstream.KeyValue
	if policy.rollouts.channel != nil {
		if releaseChannel, err = openChannelBucket(ctx, runtime.JetStream(), cfg.NATS.Replicas); err != nil {
			return err
		}
		release := releaseGate(releaseChannel)
		if seats := restartGate; seats != nil {
			restartGate = func(ctx context.Context, node string, desired host.Desired) (bool, error) {
				if granted, err := seats(ctx, node, desired); err != nil || !granted {
					return granted, err
				}
				return release(ctx, node, desired)
			}
		} else {
			restartGate = release
		}
	}
	// A cell that enrolls hosts issues its placed roles' NATS identities with
	// the same issuer (TS-651).
	var roleIdentity host.RoleIdentityIssuer
	if managed != nil {
		issuer, err := loadHostIssuer(cfg, runtime)
		if err != nil {
			return err
		}
		roleIdentity = roleIdentityIssuer(issuer, runtime, cfg.NATS.Replicas)
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
				TerraBaseCA:                 terraBaseCA,
				RoleIdentity:                roleIdentity,
				NodeAddress:                 services.nodeAddress,
				RestartGate:                 restartGate,
			})
		}, nil)
	if err != nil {
		return err
	}
	planner.hosts = hostController
	// One release fence takes nodes out of rotation for service releases,
	// controller rollouts and node operations (TS-632).
	var fences *releaseFence
	var networkControl *netbirdRollout
	// The node scaler publishes its pool nodes' addresses to the fence once it starts.
	var poolScaler atomic.Pointer[nodescale.Scaler]
	if releaseChannel != nil {
		fences = &releaseFence{kv: releaseChannel, hosts: hostController, fencer: control,
			spec:  withPoolAddresses(services.releaseFence, &poolScaler),
			seats: seatStore != nil,
			open: func(context.Context) (lb.API, error) {
				factory, err := ociclient.InstancePrincipal(region)
				if err != nil {
					return nil, err
				}
				return lb.NewSDKAPI(factory)
			}}
		policy.rollouts.fence = fences
		// serverOf is the NATS server name of the controller on node's VM,
		// which a host grant can name apart from the server (TS-609).
		serverOf := func(node string) (string, bool) {
			for _, id := range cfg.NATS.Embedded.BrokerIDs {
				if services.controllerNode(cfg.NATS.Cell, id) == node {
					return natscell.ServerName(cfg.NATS.Cell, id), true
				}
			}
			return "", false
		}
		policy.nodes = newNodeOps(fences, func(context.Context) (nodeCompute, error) { return newOCINodeCompute(region) },
			func(ctx context.Context, node string) error {
				server, controller := serverOf(node)
				gate := rolloutexec.ClusterGate{Cluster: runtime, ServerOf: func(string) (string, bool) { return server, true }}
				if !controller {
					return gate.Check(ctx, rollout.Record{Kind: rollout.KindHost}, "")
				}
				return gate.Check(ctx, rollout.Record{Kind: rollout.KindController}, node)
			})
		policy.nodes.controllers = func(node string) bool {
			_, controller := serverOf(node)
			return controller
		}
		policy.nodes.pool = func(node string) bool {
			running := poolScaler.Load()
			if running == nil {
				return false
			}
			// A just-named pool node has no private IP yet; the scaler owns it all the same.
			_, owned := running.Addresses()[node]
			return owned
		}
		networkControl = &netbirdRollout{cell: cfg.NATS.Cell, fence: fences, services: services, nodes: policy.nodes, key: responseKey, cfg: cfg, fleet: fleet, artifacts: service.Artifacts(), conn: runtime.Conn(), runtime: runtime}
		hostController.SetNetBirdSink(networkControl)
		policy.nodes.desired = hostController
		policy.nodes.forget = func(ctx context.Context, instanceID string) error {
			grants, err := hostenroll.OpenGrantStore(ctx, runtime.JetStream(), cfg.NATS.Replicas)
			if err != nil {
				return err
			}
			return grants.Forget(ctx, instanceID)
		}
	}
	// Cell specs verify with the cell's roots, so the root chain opens first.
	if services.roots != nil {
		services.roots.fencer = control
		if _, _, err := retryControllerOpen(ctx, "open regional root chain", fullClusterReady, false,
			func(attempt context.Context) (struct{}, error) {
				return struct{}{}, services.roots.open(attempt, runtime.JetStream(), cfg.NATS.Replicas)
			}, nil); err != nil {
			return err
		}
	}
	if _, _, err := retryControllerOpen(ctx, "open regional cell spec", fullClusterReady, false,
		func(attempt context.Context) (struct{}, error) {
			return struct{}{}, services.open(attempt, runtime.JetStream(), cfg.NATS.Replicas)
		}, nil); err != nil {
		return err
	}
	costStore, _, err := retryControllerOpen(ctx, "open OCI cost report", fullClusterReady, false,
		func(attempt context.Context) (*ocicost.Store, error) {
			return ocicost.OpenStore(attempt, runtime.JetStream(), cfg.NATS.Replicas)
		}, nil)
	if err != nil {
		return err
	}
	costViews := &ociCostViews{cell: cfg.NATS.Cell, store: costStore}
	profiles, specs := services.effective()
	nativeReleases.hosts, nativeReleases.fences = hostController, fences
	var nativeMemberCA []byte
	if terraBaseCA != nil {
		nativeMemberCA = terraBaseCA.CertificatePEM()
	}
	nativeReleases.canary = newSmokeGate(nativeMemberCA).check
	workloadReconciler, hostLoad, err := startWorkloadAutoscale(cfg.NATS.Cell, cfg.Controller.Autoscale,
		profiles, specs, hostController, control, nativeReleases)
	if err != nil {
		return err
	}
	planner.workloads = workloadReconciler
	telemetry.usage.SetExpected(hostController.ExpectedUsage)
	inventoryCtx, stopInventory := context.WithCancel(ctx)
	defer stopInventory()
	go func() {
		for {
			attempt, cancel := context.WithTimeout(inventoryCtx, 10*time.Second)
			err := hostController.InitializeUsageHistory(attempt)
			cancel()
			if err != nil {
				slog.DebugContext(attempt, "capacity inventory baseline unavailable", observability.ComponentKey, "capacity", "error", err)
			}
			select {
			case <-inventoryCtx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
	hostController.SetLoadSink(func(origin hostload.Origin, report hostload.Report) error {
		return hostLoad.recordCommitted(ctx, nativeReleases, telemetry, origin, report)
	})
	services.changed = func(profiles map[string]WorkloadProfile, specs []workload.ServiceSpec) {
		resources := profileResources(profiles)
		if err := workloadReconciler.SetServices(specs, resources); err != nil {
			slog.ErrorContext(ctx, "reconciler refused the adopted cell spec", observability.ComponentKey, "cellspec", "error", err)
		}
	}
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
	rolloutKnownBadReleases := newRolloutKnownBad()
	if managed != nil {
		placementConfig := withKnownBad(managed.placementConfig(cfg.NATS.Cell,
			func(err error) {
				changed := placementHolds.recordChange("reconciliation error: " + err.Error())
				slog.WarnContext(ctx, "TerraBase placement reconciliation failed", observability.ComponentKey, "placement",
					"error", err, "repeated", !changed)
			},
			func(reason string) {
				changed := placementHolds.recordChange(reason)
				slog.InfoContext(ctx, "TerraBase placement held", observability.ComponentKey, "placement",
					"reason", reason, observability.EventKey, changed)
				holdDecisions.record(ctx, reason, time.Now())
			}), rolloutKnownBadReleases)
		placementConfig.AllowedImages = services.hostImages
		managedController, err = placement.StartController(ctx, placementConfig,
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
	if networkControl != nil {
		go networkControl.meshListener(runCtx)
		recoverySub, err := networkControl.serveRecovery(runCtx, netbirdSSH)
		if err != nil {
			return fmt.Errorf("serve NetBird recovery proofs: %w", err)
		}
		defer recoverySub.Unsubscribe()
	}
	var enrollmentErrors <-chan error
	var managedEnrollment *managedHostEnrollment
	// One node pool serves enrollment and the scaler. It binds in the
	// background, since IMDS or OCI may not answer yet. Without a managed
	// runtime there is no pool: pool nodes are refused.
	var pool *nodePoolBinding
	if managed != nil {
		pool = &nodePoolBinding{}
		server, listener, serveErrors, err := startManagedHostEnrollment(runCtx, cfg, runtime,
			managed, fleet, control, placementStore, hostController, registrationVerifier, responseKey, control,
			services, pool)
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
		go bindNodePool(runCtx, pool, nodePoolRetry, func(ctx context.Context) (boundNodePool, error) {
			return bindNodeScaler(ctx, nodeScaling{cell: cfg.NATS.Cell, js: runtime.JetStream(),
				replicas: cfg.NATS.Replicas, ready: fullClusterReady,
				hosts: hostController, load: hostLoad, global: global, fencer: control, fences: fences,
				enrollment: managedEnrollment, scaler: &poolScaler, costViews: costViews})
		})
	}
	var scaleStatus func() *nodescale.Status
	if pool != nil {
		scaleStatus = pool.scaleStatus
	}
	apiErrors, err := startMachinesAPI(runCtx, cfg, runtime, control, fullClusterReady, telemetry)
	if err != nil {
		return err
	}
	var terminalRuntime *managedTerminalRuntime
	if managed != nil {
		terminalRuntime = &managedTerminalRuntime{
			control: control, placements: placementStore, hosts: hostController,
			executor: terminalExecutor, enrollment: managedEnrollment,
			requireEnrollment: true,
		}
	}
	artifactSub, err := serveArtifactAdmission(runCtx, runtime.Conn(), cfg.NATS.Cell, control, service)
	if err != nil {
		return fmt.Errorf("serve artifact admission: %w", err)
	}
	defer artifactSub.Unsubscribe()
	enrollmentSub, err := serveHostEnrollment(runCtx, runtime.Conn(), cfg.NATS.Cell, policy, control, hostController,
		managedEnrollment, services)
	if err != nil {
		return fmt.Errorf("serve host enrollment: %w", err)
	}
	defer enrollmentSub.Unsubscribe()
	if global.writer != nil {
		relaySub, err := serveCellSpecRelay(runCtx, runtime.Conn(), cfg, policy, global)
		if err != nil {
			return fmt.Errorf("serve cell spec relay: %w", err)
		}
		defer relaySub.Unsubscribe()
	}
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
	rollouts, err := startRollouts(runCtx, cfg, runtime.JetStream(), control, fullClusterReady, rolloutKnownBadReleases)
	if err != nil {
		return fmt.Errorf("start rollout store: %w", err)
	}
	policy.rollouts.store.Store(rollouts)
	rolloutExecutor, err := policy.rollouts.start(runCtx, cfg, runtime, control, responseKey, hostController)
	if err != nil {
		return fmt.Errorf("start rollout executor: %w", err)
	}
	hostController.SetRolloutSink(policy.rollouts)
	// The home allocates node growth under the monthly budget. Every region
	// feeds the budget insight from the capacity document it reads.
	allocator := startCapacityAllocator(runCtx, global, telemetry.regionRollups, runtime.JetStream(),
		cfg.NATS.Replicas, services.atlasConfig)
	if err := startBudgetSet(runCtx, runtime.Conn(), global); err != nil {
		return fmt.Errorf("serve budget requests: %w", err)
	}
	// The page shows this region's status from the rollup every member follows,
	// so a follower shows what the leader published.
	capacitySource := &capacityPage{conn: runtime.Conn(), global: global, scale: func() *nodescale.Status {
		for _, region := range telemetry.regionRollups() {
			if strings.EqualFold(region.Cell, cfg.NATS.Cell) && region.Rollup != nil {
				return region.Rollup.Scale
			}
		}
		return nil
	}}
	// runController refused a configuration without an embedded broker at
	// its top, so Embedded is always set here.
	linkSupervisor := &regionLinkSupervisor{cell: cfg.NATS.Cell, member: cfg.NATS.Instance,
		reconnect: runtime.ReconnectInterRegion, recorder: telemetry.journal}
	telemetry.registry.RegisterWriter(linkSupervisor.writeMetrics)
	go costViews.run(runCtx)
	if err := telemetry.attachController(runCtx, controllerObservation{nats: runtime, replicas: cfg.NATS.Replicas,
		brokerIDs: cfg.NATS.Embedded.BrokerIDs, authority: control, placements: placementStore,
		holds: placementHolds, autoscalers: workloadReconciler, hostLoad: hostLoad, hosts: hostController, peers: peers,
		linkProbes:            linkSupervisor.snapshot,
		nativeTerraBaseRegion: func() string { return services.profiles()[terrabase.Role].Env[terrabase.EnvRegion] },
		cost:                  costViews.view, costRollup: costViews.rollup,
		rollouts: rollouts, budgets: capacityBudgets{global: global, allocator: allocator}, ociResources: ociReconcile.resources(),
		credentials: controllerCredentialFiles(cfg),
		kvSnapshots: kvSnapshots,
		nodes:       topologySource(cfg.NATS.Cell, cfg.NATS.Embedded.BrokerIDs, services, hostController, policy.nodes),
		scale:       scaleStatus,
		capacity:    capacitySource},
		[]observability.FilesystemRole{{Role: "boot", Path: "/"}, {Role: "nats", Path: cfg.NATS.Embedded.StoreDir}}); err != nil {
		return fmt.Errorf("attach controller observability: %w", err)
	}
	// A slot for every worker with room to spare, so no sender blocks
	// shutdown.
	workerErrors := make(chan error, 32)
	var workers sync.WaitGroup
	providers := telemetry.providers.Load()
	if providers == nil {
		return errors.New("controller region telemetry provider is missing")
	}
	regions := providers.Probes
	if regions == nil || regions.Links == nil {
		return errors.New("controller region link probe source is missing")
	}
	linkSupervisor.source = regions
	startRegionSuggestions(runCtx, cfg, runtime.JetStream(), global, telemetry.regionRollups, fullClusterReady, capacitySource)
	workers.Go(func() { workerErrors <- linkSupervisor.Run(runCtx) })
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
	if seatStore != nil {
		seats := newSeatController(cfg, seatStore, control, hostController, services.profiles, ociReconcile)
		seats.Hold = policy.rollouts.hostRolloutActive
		workers.Go(func() { workerErrors <- seats.Run(runCtx) })
	}
	if membershipSupervisor != nil {
		workers.Go(func() { workerErrors <- membershipSupervisor.Run(runCtx) })
	}
	workers.Go(func() { workerErrors <- workloadReconciler.Run(runCtx) })
	atlasPublisher := &atlas.Loop{Publisher: atlas.Publisher{HTTP: &http.Client{Timeout: atlas.Interval}},
		Config: atlasRoster(services.atlasConfig, cfg.NATS.Cell, peers), Authority: control, LoadKey: atlas.VaultKey}
	workers.Go(func() { workerErrors <- atlasPublisher.Run(runCtx) })
	workers.Go(func() { workerErrors <- services.Run(runCtx) })
	workers.Go(func() { workerErrors <- nativeReleases.run(runCtx) })
	workers.Go(func() {
		workerErrors <- artifactStoreKeeper{control: control, service: service, hosts: hostController,
			quota: services.artifactStoreMaxBytes, storeDir: cfg.NATS.Embedded.StoreDir, netbird: networkControl,
			nativeHistory: nativeReleases}.Run(runCtx)
	})
	if global.writer == nil {
		workers.Go(func() {
			workerErrors <- services.followRelayedSpecs(runCtx, global.reader, policy, control, hostController)
		})
	}
	workers.Go(func() { runRegionRegistry(runCtx, runtime.Conn(), cfg, control, global, peers) })
	if policy.rollouts.channel != nil {
		releases := &serviceReleases{js: runtime.JetStream(), cell: cfg.NATS.Cell, channel: policy.rollouts.channel, deliveries: service,
			hosts: hostController, profiles: services.profiles, fencer: control, fences: fences, history: nativeReleases,
			policy: policy, roots: policy.rollouts.roots.current, environment: policy.rollouts.environment}
		workers.Go(func() { releases.run(runCtx, runtime.JetStream(), cfg.NATS.Replicas) })
	}
	if policy.nodes != nil {
		workers.Go(func() { policy.nodes.run(runCtx) })
		edge := newEdgeReconciler(cfg.NATS.Cell, fences)
		edge.ops = policy.nodes
		workers.Go(func() { edge.run(runCtx) })
	}
	if networkControl != nil {
		workers.Go(func() { networkControl.run(runCtx) })
	}
	workers.Go(func() { workerErrors <- rolloutExecutor(runCtx) })
	workers.Go(func() { policy.rollouts.publishProofs(runCtx, cfg, runtime, responseKey) })
	if services.roots != nil {
		workers.Go(func() { workerErrors <- services.roots.Run(runCtx) })

		workers.Go(func() { runMaterialGenerationStager(runCtx, services.roots) })

	}
	if enrollmentErrors != nil {
		workers.Go(func() { workerErrors <- <-enrollmentErrors })
	}
	// A signed config's Machines API (lab only) serves alone; otherwise the
	// cell spec's machines_api section turns it on.
	if cfg.Controller.MachinesAPI == nil && cfg.NATS.Embedded != nil {
		workers.Go(func() {
			workerErrors <- machinesAPILoop(runCtx, cfg, runtime, control, fullClusterReady, services.machinesAPI, telemetry)
		})
	}
	if apiErrors != nil {
		workers.Go(func() { workerErrors <- <-apiErrors })
	}
	// The cell spec's dashboard section serves the dashboard on this node's
	// NetBird address beside the signed observability listener.
	workers.Go(func() { telemetry.dashboardLoop(runCtx, services.dashboard, localNetBirdAddresses, readDashboardToken) })

	workers.Go(func() {
		runNetBirdManagement(runCtx, control)
	})
	workers.Go(func() { workerErrors <- newOCICostCollector(cfg.NATS.Cell, costStore, control).Run(runCtx) })
	workers.Go(func() { workerErrors <- newOCICostTagger(cfg.NATS.Cell, control).Run(runCtx) })

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
	policy.rollouts.ready.Store(true)
	slog.InfoContext(ctx, "controller ready", observability.ComponentKey, "controller", observability.EventKey, true, "candidate_id", candidateID)
	fmt.Fprintf(output, "controller %s ready in cell %s via %s\n", cfg.NATS.Instance, cfg.NATS.Cell, runtime.URL())
	if err := notifier.Ready("controller " + cfg.NATS.Instance + " ready in cell " + cfg.NATS.Cell); err != nil {
		slog.WarnContext(ctx, "systemd readiness notification failed", observability.ComponentKey, "controller", "error", err)
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
		slog.WarnContext(attemptCtx, "controller startup step retrying with embedded NATS running",
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
		errors.Is(err, authority.ErrConflict) || errors.Is(err, delivery.ErrStoreNotReady) ||
		errors.Is(err, host.ErrStateNotReady) {
		return true
	}
	apiErr, ok := errors.AsType[*jetstream.APIError](err)
	if !ok {
		return false
	}
	return apiErr.ErrorCode == 10005 || apiErr.Code >= 500 &&
		!errors.Is(err, jetstream.ErrJetStreamNotEnabled) &&
		!errors.Is(err, jetstream.ErrJetStreamNotEnabledForAccount)
}
