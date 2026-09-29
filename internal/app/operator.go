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
	"uuid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

const (
	operatorBindRecoveryTimeout      = 15 * time.Second
	operatorBindAttemptTimeout       = 5 * time.Second
	operatorAdmissionRecoveryTimeout = 30 * time.Second
	operatorAdmissionAttemptTimeout  = 10 * time.Second
	operatorSubmitSetupTimeout       = 10 * time.Second
	operatorRetryInitialBackoff      = 100 * time.Millisecond
	operatorRetryMaxBackoff          = 800 * time.Millisecond
)

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
		return errors.New("usage: operator <hosts|host-register|host-enrollment-revoke|material-prepare|material-credentials|material-credentials-status|placement-apply|managed-update-prepare|placement-list|terminal-plan|terminal-apply|terminal-status|backup-start|backup-abort|backup-status|broker-claim-apply|artifact-push|deploy|rollback|status> --config FILE")
	}
	operation := args[0]
	flags := flag.NewFlagSet("operator "+operation, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "JSON role configuration")
	artifactPath := flags.String("file", "", "artifact file to upload")
	repository := flags.String("repository", "", "HTTPS source repository")
	commit := flags.String("commit", "", "source commit SHA")
	treeDigest := flags.String("tree-digest", "", "source tree SHA-256")
	role := flags.String("role", "", "artifact role")
	environment := flags.String("environment", "", "artifact environment")
	intentPath := flags.String("intent", "", "JSON delivery intent")
	databaseID := flags.String("database-id", "", "managed database ID")
	partitionID := flags.String("partition-id", "", "managed partition ID")
	registrationPath := flags.String("registration", "", "JSON host registration")
	instanceID := flags.String("instance-id", "", "managed OCI host instance ID")
	operationID := flags.String("operation-id", "", "operation ID (required for backup-abort; optional for current backup-status)")
	fingerprint := flags.String("fingerprint", "", "expected intent SHA-256 fingerprint")
	expectedSequence := flags.String("expected-sequence", "", "expected durable broker claim sequence")
	var forwards operatorForwardFlags
	flags.Var(&forwards, "nats-forward", "transient PRIVATE_IP:4222=LOOPBACK_IP:PORT Bastion forward (repeatable)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected operator arguments")
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
		return err
	}
	defer runtime.Close()
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := runtime.WaitForCluster(readyCtx, cfg.NATS.Replicas); err != nil {
		return err
	}
	switch operation {
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
		return operatorBackupOperation(ctx, cfg, runtime, "start", *databaseID, *partitionID, "", output)
	case "backup-abort":
		return operatorBackupOperation(ctx, cfg, runtime, "abort", *databaseID, *partitionID, *operationID, output)
	case "backup-status":
		return operatorBackupOperation(ctx, cfg, runtime, "status", *databaseID, *partitionID, *operationID, output)
	case "material-prepare":
		if *intentPath == "" {
			return errors.New("material-prepare requires --intent FILE")
		}
		return operatorMaterialPrepare(ctx, cfg, runtime, *intentPath, output)
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
	service, activeRuntime, err := bindArtifactPushClient(ctx, cfg, runtime)
	if activeRuntime != nil && activeRuntime != runtime {
		defer activeRuntime.Close()
	}
	if err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	record, signedClaim, err := service.PrepareArtifact(ctx, file, claim)
	if err != nil {
		return err
	}
	if err := requestArtifactAdmission(ctx, activeRuntime.Conn(), cfg.NATS.Cell, record, signedClaim); err != nil {
		return err
	}
	return printJSON(output, record)
}

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
			requestErr = errors.New(response.Error)
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
	if intent.SchemaVersion == 0 {
		intent.SchemaVersion = delivery.SchemaVersion
	}
	if intent.Cell == "" {
		intent.Cell = cfg.NATS.Cell
	}
	if intent.Cell != cfg.NATS.Cell {
		return errors.New("delivery intent belongs to another cell")
	}
	if intent.OperationID == "" {
		intent.OperationID = uuid.New().String()
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
			return err
		}
		intent.AuthorityEpoch = epoch
	}
	fingerprint, err := intent.Fingerprint()
	if err != nil {
		return err
	}
	service, err := retryOperatorMetadata(setupCtx, func(attemptCtx context.Context) (*delivery.Service, error) {
		return operatorService(attemptCtx, cfg, runtime, true)
	})
	if err != nil {
		return fmt.Errorf("bind delivery client: %w", err)
	}
	if err := service.Submit(ctx, intent); err != nil {
		return fmt.Errorf("submit operation %s fingerprint %s: %w", intent.OperationID, fingerprint, err)
	}
	return printJSON(output, struct {
		OperationID string `json:"operationId"`
		Fingerprint string `json:"fingerprint"`
		Status      string `json:"status"`
	}{intent.OperationID, fingerprint, "submitted"})
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
	reader, err := authority.OpenReader(ctx, runtime.JetStream(), cfg.NATS.Cell)
	if err != nil {
		return err
	}
	hostReader, err := host.NewReader(ctx, host.ReaderConfig{Cell: cfg.NATS.Cell, Conn: runtime.Conn(), JS: runtime.JetStream(), StateReplicas: cfg.NATS.Replicas, HostMutations: reader})
	if err != nil {
		return err
	}
	statuses, err := hostReader.ListHosts(ctx)
	if err != nil {
		return err
	}
	return printJSON(output, statuses)
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
