package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	staged "git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

const (
	operatorBindRecoveryTimeout     = 15 * time.Second
	operatorBindAttemptTimeout      = 5 * time.Second
	operatorAdmissionAttemptTimeout = 10 * time.Second
	operatorSubmitSetupTimeout      = 10 * time.Second
	operatorRetryInitialBackoff     = 100 * time.Millisecond
	operatorRetryMaxBackoff         = 800 * time.Millisecond
)

// operatorAdmissionRecoveryTimeout bounds the replays of one signed artifact
// claim; tests shorten it.
var operatorAdmissionRecoveryTimeout = 30 * time.Second

type operatorForwardFlags map[string]string

func (*operatorForwardFlags) String() string { return "" }

func (forwards *operatorForwardFlags) Set(value string) error {
	original, destination, ok := strings.Cut(value, "=")
	if !ok || original == "" || destination == "" || strings.Contains(destination, "=") {
		return errors.New("--nats-forward requires PRIVATE_IP:4222=LOOPBACK_IP:PORT")
	}
	if *forwards == nil {
		*forwards = make(operatorForwardFlags)
	}
	if _, duplicate := (*forwards)[original]; duplicate {
		return errors.New("duplicate --nats-forward controller")
	}
	(*forwards)[original] = destination
	return nil
}

func runOperator(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: operator <terrabase-release|ts-auth-release|terrabase-deploy|terrabase-update|terrabase-sync|terrabase-status|terrabase-walkthrough|hosts|host-register|host-enrollment-revoke|material-credentials|material-credentials-status|placement-apply|managed-update-prepare|placement-list|terminal-plan|terminal-apply|terminal-status|backup-start|backup-abort|backup-status|broker-claim-apply|artifact-push|netbird-stage|deploy|rollback|trust-roots|trust-rotate|material-generation <publish|status|arm|disarm>|status> --config FILE")
	}
	operation := args[0]
	if operation == "material-generation" && len(args) > 1 {
		operation, args = operation+"-"+args[1], args[1:]
	}
	if operation == "terrabase-walkthrough" {
		// The customer walkthrough uses only the deployment state and the
		// members' HTTPS listeners, never the controller or NATS.
		return runTerraBaseWalkthrough(ctx, args[1:], output)
	}
	if operation == "terrabase-sync" {
		return runTerraBaseSync(ctx, args[1:], output)
	}
	flags := flag.NewFlagSet("operator "+operation, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "JSON role configuration")
	artifactPath := flags.String("file", "", "artifact file to upload")
	architecture := flags.String("architecture", "", "netbird-stage: artifact architecture (arm64 or amd64)")
	flags.StringVar(artifactPath, "f", "", "diff, apply: cell spec file")
	repository := flags.String("repository", "", "HTTPS source repository")
	commit := flags.String("commit", "", "source commit SHA")
	treeDigest := flags.String("tree-digest", "", "source tree SHA-256")
	role := flags.String("role", "", "artifact role")
	environment := flags.String("environment", "", "artifact environment")
	intentPath := flags.String("intent", "", "JSON delivery intent")
	planPath := flags.String("plan", "", "TerraBase deployment plan JSON")
	statePath := flags.String("state", "", "owner-only TerraBase deployment state directory")
	wait := flags.Duration("wait", 0, "status: wait until every member serves; update: bound each seat's outcome wait")
	qualification := flags.String("qualification", "", "TerraBase release qualification.json")
	releaseBinary := flags.String("binary", "", "TerraBase release executable")
	releaseChecksum := flags.String("sha256", "", "terrabase-release, ts-auth-release: the executable's .sha256 release asset")
	sourceCheckout := flags.String("source-checkout", "", "terrabase-release, ts-auth-release: source checkout containing --commit")
	profilePath := flags.String("profile", "", "terrabase-release, ts-auth-release: the role's signed controller workloads profile JSON")
	sourceDigest := flags.String("source-digest", "", "TerraBase release prepared-source digest record")
	compatibilityActor := flags.String("compatibility-actor", "", "trusted compatibility signer actor")
	compatibilityKey := flags.String("compatibility-key", "", "owner-only compatibility signer key file")
	soak := flags.Duration("soak", staged.DefaultSoak, "update: how long a promoted seat must keep serving before the next seat (0 disables)")
	assumeCompatible := flags.Bool("assume-compatibility", false, "update: certify releases that publish no compatibility declaration as compatible (unverified)")
	databaseID := flags.String("database-id", "", "managed database ID")
	partitionID := flags.String("partition-id", "", "managed partition ID")
	registrationPath := flags.String("registration", "", "JSON host registration")
	instanceID := flags.String("instance-id", "", "managed OCI host instance ID")
	operationID := flags.String("operation-id", "", "operation ID (required for backup-abort; optional for current backup-status)")
	historyCursor := flags.String("history-cursor", "", "signed backup history continuation cursor")
	fingerprint := flags.String("fingerprint", "", "expected intent SHA-256 fingerprint")
	expectedSequence := flags.String("expected-sequence", "", "expected durable broker claim sequence")
	specPath := flags.String("spec", "", "service add, update: the role's reconciled service spec JSON")
	outPath := flags.String("out", "", "service add, update, remove: new unsigned candidate file")
	releasers := flags.String("releasers", "", "service add, update: comma-separated trusted signers that may release the role; update keeps the current ones when unset")
	node := flags.String("node", "", "service grant-host, revoke-host: the static host's server name; node: the node")
	privateIP := flags.String("private-ip", "", "service grant-host: the host's private IPv4 address")
	roles := flags.String("roles", "", "service grant-host: comma-separated roles the host runs")
	controllerSlot := flags.String("controller", "", "service grant-host: the controller slot (controller-a) whose VM a renamed node is")
	receiptPath := flags.String("receipt", "", "rollout publish: signed binary receipt or update receipt; service allow-image: signed image receipt")
	delegationPath := flags.String("delegation", "", "rollout publish, service allow-image: the receipt's root-signed delegation")
	imageID := flags.String("image-id", "", "service allow-image, revoke-image: the OCI image OCID")
	launchImage := flags.Bool("launch", false, "service allow-image: new managed hosts boot the image; revoke-image: only stop new hosts booting it")
	toGeneration := flags.Uint64("to", 0, "rollout rollback: the earlier generation to publish again")
	ocpus := flags.Float64("ocpus", 0, "node resize: the instance's OCPUs")
	newName := flags.String("new-name", "", "node rename: the node's new name")
	atlasCell := flags.String("cell", "", "atlas add-region: the region's cell, such as sfo-1")
	memoryGB := flags.Float64("memory-gb", 0, "node resize: the instance's memory in GB")
	chainPath := flags.String("chain", "", "material-generation publish: the root-signed generation chain")
	slot := flags.String("slot", "", "material-generation arm, disarm: the controller slot")
	var controllerConfigs controllerConfigFlags
	flags.Var(&controllerConfigs, "controller-config", "material-generation publish: SLOT=FILE, the slot's pinned controller.json (repeatable)")
	var forwards operatorForwardFlags
	flags.Var(&forwards, "nats-forward", "transient PRIVATE_IP:4222=LOOPBACK_IP:PORT Bastion forward (repeatable)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected operator arguments")
	}
	var rolloutRequest any
	if command, isRollout := strings.CutPrefix(operation, "rollout-"); isRollout {
		var err error
		if rolloutRequest, err = rolloutPayload(command, *receiptPath, *delegationPath, *toGeneration); err != nil {
			return err
		}
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if len(forwards) != 0 {
		if cfg.NATS.ClientRole != "operator" {
			return errors.New("NATS forwarding requires the operator role config")
		}
		cfg.NATS.OperatorForward = forwards
	}
	connection := cfg.NATS
	connection.ClientRole = "operator"
	connection, err = externalNATS(connection)
	if err != nil {
		return err
	}
	runtime, err := natscell.Start(ctx, connection)
	if err != nil {
		return classifyConnectError(err)
	}
	defer runtime.Close()
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := runtime.WaitForCluster(readyCtx, cfg.NATS.Replicas); err != nil {
		return classifyControllerError(err)
	}
	switch operation {
	case "terrabase-deploy":
		if *planPath == "" || *statePath == "" {
			return errors.New("terrabase-deploy requires --plan FILE and --state DIR")
		}
		return operatorTerraBaseDeploy(ctx, cfg, runtime, *planPath, *statePath, output)
	case "terrabase-update":
		if *statePath == "" || *qualification == "" || *releaseBinary == "" || *sourceDigest == "" ||
			*compatibilityActor == "" || *compatibilityKey == "" || *wait < 0 || *soak < 0 {
			return errors.New("terrabase-update requires --state, --qualification, --binary, --source-digest, --compatibility-actor, --compatibility-key and a nonnegative --soak")
		}
		return operatorTerraBaseUpdate(ctx, cfg, runtime, *statePath,
			terrabaseReleaseFiles{Qualification: *qualification, Binary: *releaseBinary, SourceDigest: *sourceDigest},
			terrabaseCompatibilitySigner{Actor: *compatibilityActor, KeyFile: *compatibilityKey},
			terrabaseUpdateOptions{SeatWait: *wait, Soak: *soak, AssumeCompatible: *assumeCompatible}, output)
	case "terrabase-release":
		if *releaseBinary == "" || *releaseChecksum == "" || *sourceCheckout == "" || *commit == "" ||
			*environment == "" || *profilePath == "" || *wait < 0 {
			return errors.New("terrabase-release requires --binary, --sha256, --source-checkout, --commit, --environment, --profile and a nonnegative --wait")
		}
		return operatorTerraBaseRelease(ctx, cfg, runtime, terraBaseReleaseOptions{Binary: *releaseBinary,
			Checksum: *releaseChecksum, SourceCheckout: *sourceCheckout, Commit: *commit, Environment: *environment,
			Profile: *profilePath, Wait: *wait}, output)
	case "ts-auth-release":
		if *releaseBinary == "" || *releaseChecksum == "" || *sourceCheckout == "" || *commit == "" ||
			*environment == "" || *profilePath == "" || *wait < 0 {
			return errors.New("ts-auth-release requires --binary, --sha256, --source-checkout, --commit, --environment, --profile and a nonnegative --wait")
		}
		return operatorTSAuthRelease(ctx, cfg, runtime, terraBaseReleaseOptions{Binary: *releaseBinary,
			Checksum: *releaseChecksum, SourceCheckout: *sourceCheckout, Commit: *commit, Environment: *environment,
			Profile: *profilePath, Wait: *wait}, output)
	case "terrabase-status":
		if *statePath == "" || *wait < 0 {
			return errors.New("terrabase-status requires --state DIR and a nonnegative --wait")
		}
		return operatorTerraBaseStatus(ctx, cfg, runtime, *statePath, *wait, output)
	case "hosts":
		return operatorHosts(ctx, cfg, runtime, output)
	case "host-register":
		if *registrationPath == "" {
			return errors.New("host-register requires --registration FILE")
		}
		return operatorHostRegister(ctx, cfg, runtime, *registrationPath, output)
	case "host-enrollment-revoke":
		return operatorHostEnrollmentRevoke(ctx, cfg, runtime, *instanceID, output)
	case "placement-apply":
		if *intentPath == "" {
			return errors.New("placement-apply requires --intent FILE")
		}
		return operatorPlacementApply(ctx, cfg, runtime, *intentPath, output)
	case "managed-update-prepare":
		if *intentPath == "" {
			return errors.New("managed-update-prepare requires --intent FILE")
		}
		return operatorManagedUpdatePrepare(ctx, cfg, runtime, *intentPath, output)
	case "placement-list":
		return operatorPlacementList(ctx, cfg, runtime, output)
	case "terminal-plan":
		return operatorTerminalPlan(ctx, cfg, runtime, *databaseID, *partitionID, *operationID, output)
	case "terminal-apply":
		if *intentPath == "" {
			return errors.New("terminal-apply requires --intent FILE")
		}
		return operatorTerminalApply(ctx, cfg, runtime, *intentPath, output)
	case "terminal-status":
		return operatorTerminalStatus(ctx, cfg, runtime, *databaseID, *partitionID, output)
	case "backup-start":
		return operatorBackupOperation(ctx, cfg, runtime, "start", *databaseID, *partitionID, "", "", output)
	case "backup-abort":
		return operatorBackupOperation(ctx, cfg, runtime, "abort", *databaseID, *partitionID, *operationID, "", output)
	case "backup-status":
		return operatorBackupOperation(ctx, cfg, runtime, "status", *databaseID, *partitionID, *operationID, *historyCursor, output)
	case "material-credentials":
		if *intentPath == "" {
			return errors.New("material-credentials requires --intent FILE")
		}
		return operatorMaterialCredentials(ctx, cfg, runtime, *intentPath, output)
	case "material-credentials-status":
		if *intentPath == "" {
			return errors.New("material-credentials-status requires --intent FILE")
		}
		return operatorMaterialCredentialsStatus(ctx, cfg, runtime, *intentPath, output)
	case "broker-claim-apply":
		if *artifactPath == "" || *expectedSequence == "" {
			return errors.New("broker-claim-apply requires --file and --expected-sequence")
		}
		return operatorBrokerClaimApply(ctx, cfg, runtime, *artifactPath, *expectedSequence, output)
	case "netbird-stage":
		if *artifactPath == "" || (*architecture != "arm64" && *architecture != "amd64") {
			return errors.New("netbird-stage requires --file and --architecture arm64|amd64")
		}
		return operatorNetBirdStage(ctx, cfg, runtime, *artifactPath, *architecture, output)
	case "artifact-push":
		if *artifactPath == "" || *repository == "" || *commit == "" || *treeDigest == "" || *role == "" || *environment == "" {
			return errors.New("artifact-push requires --file, --repository, --commit, --tree-digest, --role and --environment")
		}
		return operatorArtifactPush(ctx, cfg, runtime, *artifactPath, delivery.ArtifactClaimRequest{
			Source: delivery.ArtifactSource{Repository: *repository, Commit: *commit, TreeDigest: *treeDigest},
			Cell:   cfg.NATS.Cell, Role: *role, Environment: *environment,
		}, output)
	case "deploy", "rollback":
		if *intentPath == "" {
			return errors.New("deploy and rollback require --intent FILE")
		}
		return operatorSubmit(ctx, cfg, runtime, *intentPath, output)
	case "service-list", "spec-get":
		return operatorSpecGet(ctx, cfg, runtime, output)
	case "spec-diff":
		if *artifactPath == "" {
			return errors.New("diff requires -f FILE")
		}
		return operatorSpecDiff(ctx, cfg, runtime, *artifactPath, output)
	case "service-grant-host", "service-revoke-host":
		return operatorServiceHostGrant(ctx, cfg, runtime, operation == "service-grant-host", cellspec.HostGrant{
			Node: *node, PrivateIP: *privateIP, Roles: splitList(*roles), Environment: *environment, Controller: *controllerSlot},
			*outPath, output)
	case "service-allow-image", "service-revoke-image":
		return operatorServiceHostImage(ctx, cfg, runtime, operation == "service-allow-image", *launchImage, *imageID,
			*receiptPath, *delegationPath, *outPath, output)
	case "service-add", "service-update", "service-remove":
		return operatorServiceChange(ctx, cfg, runtime, strings.TrimPrefix(operation, "service-"), *role,
			*profilePath, *specPath, *releasers, *outPath, output)
	case "atlas-add-region":
		return operatorAtlasAddRegion(ctx, cfg, runtime, *atlasCell, *outPath, output)
	case "service-apply", "spec-apply":
		if *artifactPath == "" {
			return errors.New("apply requires -f SIGNED")
		}
		return operatorSpecApply(ctx, cfg, runtime, *artifactPath, output)
	case "rollout-status", "rollout-publish", "rollout-pause", "rollout-resume", "rollout-rollback":
		return operatorRollout(ctx, cfg, runtime, strings.TrimPrefix(operation, "rollout-"), rolloutRequest, output)
	case "node-status", "node-drain", "node-undrain", "node-reboot", "node-resize", "node-add", "node-retire", "node-rename":
		return operatorNode(ctx, cfg, runtime, strings.TrimPrefix(operation, "node-"),
			nodeOpRequest{Node: *node, To: *newName, OCPUs: float32(*ocpus), MemoryGB: float32(*memoryGB)}, *wait, output)
	case "material-generation-publish", "material-generation-status", "material-generation-arm",
		"material-generation-disarm":
		return operatorMaterialGeneration(ctx, cfg, runtime, strings.TrimPrefix(operation, "material-generation-"),
			*chainPath, controllerConfigs, *slot, output)
	case "trust-roots":
		return operatorTrustRoots(ctx, cfg, runtime, *outPath, output)
	case "trust-rotate":
		if *artifactPath == "" {
			return errors.New("trust-rotate requires --file SIGNED")
		}
		return operatorTrustRotate(ctx, cfg, runtime, *artifactPath, output)
	case "status":
		if *operationID == "" || !fingerprintPattern.MatchString(*fingerprint) {
			return errors.New("status requires --operation-id and lowercase SHA-256 --fingerprint")
		}
		return operatorStatus(ctx, cfg, runtime, *operationID, *fingerprint, output)
	default:
		return fmt.Errorf("unknown operator operation %q", operation)
	}
}

func operatorService(ctx context.Context, cfg Config, runtime *natscell.Runtime, signed bool) (*delivery.Service, error) {
	settings := delivery.Config{Conn: runtime.Conn(), JS: runtime.JetStream(), Cell: cfg.NATS.Cell}
	if signed {
		policy, err := buildSignerPolicy(cfg)
		if err != nil {
			return nil, err
		}
		codec, err := policy.withOperator(cfg.Operator)
		if err != nil {
			return nil, err
		}
		settings.Signer = codec
		settings.ArtifactSigner = codec
		settings.ArtifactVerifier = codec
		settings.AuthorizeArtifact = policy.authorizeArtifact
	}
	return delivery.ConnectClient(ctx, settings)
}

func operatorArtifactPush(ctx context.Context, cfg Config, runtime *natscell.Runtime, path string, claim delivery.ArtifactClaimRequest, output io.Writer) error {
	record, err := pushArtifact(ctx, cfg, runtime, path, claim)
	if err != nil {
		return err
	}
	return printJSON(output, record)
}

// pushArtifact stores the exact file bytes in the regional artifact store and
// requests their signed admission. Both effects are idempotent for one digest
// and claim, so reruns re-confirm an already admitted artifact.
func pushArtifact(ctx context.Context, cfg Config, runtime *natscell.Runtime, path string, claim delivery.ArtifactClaimRequest) (delivery.ArtifactRecord, error) {
	service, activeRuntime, err := bindArtifactPushClient(ctx, cfg, runtime)
	if activeRuntime != nil && activeRuntime != runtime {
		defer activeRuntime.Close()
	}
	if err != nil {
		return delivery.ArtifactRecord{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return delivery.ArtifactRecord{}, err
	}
	defer file.Close()
	record, signedClaim, err := service.PrepareArtifact(ctx, file, claim)
	if err != nil {
		return delivery.ArtifactRecord{}, err
	}
	if err := requestArtifactAdmission(ctx, activeRuntime.Conn(), cfg.NATS.Cell, record, signedClaim); err != nil {
		return delivery.ArtifactRecord{}, err
	}
	return record, nil
}

// errControllerRetryable marks a controller reply that declared itself
// retryable. It stays in the chain when the recovery window below expires,
// so callers still classify the failure as transient.
var errControllerRetryable = errors.New("controller reported a retryable backend failure")

// Reuse the exact signed claim during the 30-second recovery window. A replay
// can only confirm the same durable admission; the controller verifies its
// signature, expiry, authorization and stored artifact on every request.
func requestArtifactAdmission(ctx context.Context, conn *nats.Conn, cell string, record delivery.ArtifactRecord, signedClaim []byte) error {
	recoveryCtx, cancel := context.WithTimeout(ctx, operatorAdmissionRecoveryTimeout)
	defer cancel()
	backoff := operatorRetryInitialBackoff
	for {
		if err := recoveryCtx.Err(); err != nil {
			return err
		}
		requestCtx, stop := context.WithTimeout(recoveryCtx, operatorAdmissionAttemptTimeout)
		message, requestErr := conn.RequestWithContext(requestCtx, delivery.ArtifactClaimSubject(cell), signedClaim)
		attemptTimedOut := errors.Is(requestCtx.Err(), context.DeadlineExceeded)
		stop()
		if requestErr == nil {
			var response artifactAdmissionResponse
			if err := json.Unmarshal(message.Data, &response, json.RejectUnknownMembers(true)); err != nil {
				return fmt.Errorf("decode artifact admission reply: %w", err)
			}
			if response.Error == "" {
				if response.Retryable {
					return errors.New("controller returned a retryable artifact admission success")
				}
				if response.Record != record {
					return errors.New("controller admitted a different artifact record")
				}
				return nil
			}
			if !response.Retryable {
				return errors.New(response.Error)
			}
			requestErr = fmt.Errorf("%w: %s", errControllerRetryable, response.Error)
		} else if !retryableOperatorBackendError(requestErr, attemptTimedOut) {
			return fmt.Errorf("request controller artifact admission: %w", requestErr)
		}
		if err := waitOperatorRetry(recoveryCtx, backoff); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("request controller artifact admission: %w", requestErr)
		}
		backoff = min(backoff*2, operatorRetryMaxBackoff)
	}
}

// A timed-out resource bind may leave its NATS request multiplexer unhealthy.
// A typed transient metadata error can use the current connection. Both cases
// are bounded by the existing 5-second attempt and 15-second total bind times.
func bindArtifactPushClient(ctx context.Context, cfg Config, initial *natscell.Runtime) (*delivery.Service, *natscell.Runtime, error) {
	return bindArtifactPushClientWith(ctx, cfg, initial, operatorService)
}

func bindArtifactPushClientWith(ctx context.Context, cfg Config, initial *natscell.Runtime, bind func(context.Context, Config, *natscell.Runtime, bool) (*delivery.Service, error)) (*delivery.Service, *natscell.Runtime, error) {
	recoveryCtx, cancel := context.WithTimeout(ctx, operatorBindRecoveryTimeout)
	defer cancel()
	active := initial
	backoff := operatorRetryInitialBackoff
	for {
		if err := recoveryCtx.Err(); err != nil {
			return nil, active, err
		}
		bindCtx, stop := context.WithTimeout(recoveryCtx, operatorBindAttemptTimeout)
		service, err := bind(bindCtx, cfg, active, true)
		setupTimedOut := errors.Is(bindCtx.Err(), context.DeadlineExceeded)
		stop()
		if err == nil {
			return service, active, nil
		}
		if ctx.Err() != nil {
			return nil, active, ctx.Err()
		}
		if !retryableOperatorBackendError(err, setupTimedOut) || recoveryCtx.Err() != nil {
			return nil, active, fmt.Errorf("bind artifact push client: %w", err)
		}
		if setupTimedOut {
			_ = active.Close()
			connection := cfg.NATS
			connection.ClientRole = "operator"
			connection, err = externalNATS(connection)
			if err != nil {
				return nil, active, err
			}
			active, err = natscell.Start(recoveryCtx, connection)
			if err != nil {
				return nil, active, fmt.Errorf("restart artifact push connection: %w", err)
			}
			readyCtx, readyCancel := context.WithTimeout(recoveryCtx, 10*time.Second)
			err = active.WaitForCluster(readyCtx, cfg.NATS.Replicas)
			readyCancel()
			if err != nil {
				_ = active.Close()
				return nil, active, fmt.Errorf("wait for restarted artifact push connection: %w", err)
			}
		}
		if err := waitOperatorRetry(recoveryCtx, backoff); err != nil {
			if ctx.Err() != nil {
				return nil, active, ctx.Err()
			}
			return nil, active, fmt.Errorf("bind artifact push client: %w", err)
		}
		backoff = min(backoff*2, operatorRetryMaxBackoff)
	}
}

func retryableOperatorBackendError(err error, attemptTimedOut bool) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return attemptTimedOut
	}
	if errors.Is(err, nats.ErrTimeout) || errors.Is(err, nats.ErrNoResponders) ||
		errors.Is(err, nats.ErrDisconnected) || errors.Is(err, nats.ErrNoServers) ||
		errors.Is(err, jetstream.ErrNoStreamResponse) {
		return true
	}
	if api, ok := errors.AsType[*jetstream.APIError](err); ok {
		return api.Code == 503 && api.ErrorCode == 10008
	}
	if api, ok := errors.AsType[*nats.APIError](err); ok {
		return api.Code == 503 && api.ErrorCode == 10008
	}
	return false
}

func waitOperatorRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func retryOperatorMetadata[T any](ctx context.Context, call func(context.Context) (T, error)) (T, error) {
	var zero T
	backoff := operatorRetryInitialBackoff
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		attemptCtx, stop := context.WithTimeout(ctx, operatorBindAttemptTimeout)
		value, err := call(attemptCtx)
		attemptTimedOut := errors.Is(attemptCtx.Err(), context.DeadlineExceeded)
		stop()
		if err == nil {
			return value, nil
		}
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
		if !retryableOperatorBackendError(err, attemptTimedOut) {
			return zero, err
		}
		if err := waitOperatorRetry(ctx, backoff); err != nil {
			return zero, err
		}
		backoff = min(backoff*2, operatorRetryMaxBackoff)
	}
}

func observeOperatorAuthority(ctx context.Context, observe func(context.Context) (authority.Snapshot, error)) (uint64, error) {
	snapshot, err := retryOperatorMetadata(ctx, observe)
	if err != nil {
		return 0, fmt.Errorf("observe regional authority: %w", err)
	}
	if !snapshot.Ready || snapshot.Reason != "observed" || snapshot.Epoch == 0 || !time.Now().Before(snapshot.ExpiresAt) {
		return 0, errors.New("regional authority lease is not current")
	}
	return snapshot.Epoch, nil
}

func operatorSubmit(ctx context.Context, cfg Config, runtime *natscell.Runtime, path string, output io.Writer) error {
	data, err := readBoundedConfigFile(path)
	if err != nil {
		return err
	}
	if len(data) > delivery.MaxIntentBytes {
		return errors.New("intent file exceeds delivery size limit")
	}
	var intent delivery.Intent
	if err := json.Unmarshal(data, &intent, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("parse delivery intent: %w", err)
	}
	intent, fingerprint, err := submitIntent(ctx, cfg, runtime, intent)
	if err != nil {
		return err
	}
	return printJSON(output, struct {
		OperationID string `json:"operationId"`
		Fingerprint string `json:"fingerprint"`
		Status      string `json:"status"`
	}{intent.OperationID, fingerprint, "submitted"})
}

// submitIntent fills an intent's defaults, signs and submits it, and returns
// the submitted intent with its fingerprint. The fingerprint is set once
// Submit was called, even when it failed: only then may the intent have been
// published.
func submitIntent(ctx context.Context, cfg Config, runtime *natscell.Runtime, intent delivery.Intent) (delivery.Intent, string, error) {
	if intent.SchemaVersion == 0 {
		intent.SchemaVersion = delivery.SchemaVersion
	}
	if intent.Cell == "" {
		intent.Cell = cfg.NATS.Cell
	}
	if intent.Cell != cfg.NATS.Cell {
		return intent, "", errors.New("delivery intent belongs to another cell")
	}
	if intent.OperationID == "" {
		intent.OperationID = entityid.New()
	}
	// Both setup calls are read-only. Keep their total recovery within ten
	// seconds, and never replay Submit after an ambiguous intent publish.
	setupCtx, stopSetup := context.WithTimeout(ctx, operatorSubmitSetupTimeout)
	defer stopSetup()
	if intent.AuthorityEpoch == 0 {
		epoch, err := observeOperatorAuthority(setupCtx, func(attemptCtx context.Context) (authority.Snapshot, error) {
			return authority.Observe(attemptCtx, runtime.JetStream(), cfg.NATS.Cell)
		})
		if err != nil {
			return intent, "", err
		}
		intent.AuthorityEpoch = epoch
	}
	fingerprint, err := intent.Fingerprint()
	if err != nil {
		return intent, "", err
	}
	service, err := retryOperatorMetadata(setupCtx, func(attemptCtx context.Context) (*delivery.Service, error) {
		return operatorService(attemptCtx, cfg, runtime, true)
	})
	if err != nil {
		return intent, "", fmt.Errorf("bind delivery client: %w", err)
	}
	if err := service.Submit(ctx, intent); err != nil {
		return intent, fingerprint, fmt.Errorf("submit operation %s fingerprint %s: %w", intent.OperationID, fingerprint, err)
	}
	return intent, fingerprint, nil
}

func operatorStatus(ctx context.Context, cfg Config, runtime *natscell.Runtime, operationID, fingerprint string, output io.Writer) error {
	service, err := operatorService(ctx, cfg, runtime, false)
	if err != nil {
		return err
	}
	receipt, err := service.Status(ctx, operationID)
	if errors.Is(err, delivery.ErrPending) {
		return printJSON(output, struct {
			OperationID string `json:"operationId"`
			Fingerprint string `json:"fingerprint"`
			Status      string `json:"status"`
		}{operationID, fingerprint, "pending"})
	}
	if err != nil {
		return err
	}
	if receipt.Fingerprint != fingerprint {
		return delivery.ErrConflict
	}
	return printJSON(output, receipt)
}

func operatorHosts(ctx context.Context, cfg Config, runtime *natscell.Runtime, output io.Writer) error {
	hostReader, err := operatorHostReader(ctx, cfg, runtime)
	if err != nil {
		return err
	}
	statuses, err := hostReader.ListHosts(ctx)
	if err != nil {
		return err
	}
	return printJSON(output, statuses)
}

func operatorHostReader(ctx context.Context, cfg Config, runtime *natscell.Runtime) (*host.Reader, error) {
	reader, err := authority.OpenReader(ctx, runtime.JetStream(), cfg.NATS.Cell)
	if err != nil {
		return nil, err
	}
	return host.NewReader(ctx, host.ReaderConfig{Cell: cfg.NATS.Cell, Conn: runtime.Conn(), JS: runtime.JetStream(),
		StateReplicas: cfg.NATS.Replicas, HostMutations: reader})
}

func printJSON(output io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, string(data))
	return err
}

type artifactAdmissionResponse struct {
	Record    delivery.ArtifactRecord `json:"record"`
	Error     string                  `json:"error,omitempty"`
	Retryable bool                    `json:"retryable,omitzero"`
}
