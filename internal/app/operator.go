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
	"time"
	"uuid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nats.go"
)

var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func runOperator(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: operator <hosts|host-register|placement-apply|artifact-push|deploy|rollback|status> --config FILE")
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
	registrationPath := flags.String("registration", "", "JSON host registration")
	operationID := flags.String("operation-id", "", "delivery operation ID")
	fingerprint := flags.String("fingerprint", "", "expected intent SHA-256 fingerprint")
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
	case "placement-apply":
		if *intentPath == "" {
			return errors.New("placement-apply requires --intent FILE")
		}
		return operatorPlacementApply(ctx, cfg, runtime, *intentPath, output)
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
	settings := delivery.Config{JS: runtime.JetStream(), Cell: cfg.NATS.Cell}
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
	service, err := operatorService(ctx, cfg, runtime, true)
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
	for attempt := range 3 {
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		message, requestErr := runtime.Conn().RequestWithContext(requestCtx, delivery.ArtifactClaimSubject(cfg.NATS.Cell), signedClaim)
		cancel()
		if requestErr == nil {
			var response artifactAdmissionResponse
			if err := json.Unmarshal(message.Data, &response, json.RejectUnknownMembers(true)); err != nil {
				return fmt.Errorf("decode artifact admission reply: %w", err)
			}
			if response.Error != "" {
				return errors.New(response.Error)
			}
			if response.Record != record {
				return errors.New("controller admitted a different artifact record")
			}
			return printJSON(output, response.Record)
		}
		if (!errors.Is(requestErr, nats.ErrTimeout) && !errors.Is(requestErr, context.DeadlineExceeded)) || attempt == 2 {
			return fmt.Errorf("request controller artifact admission: %w", requestErr)
		}
	}
	return errors.New("artifact admission request exhausted")
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
	if intent.AuthorityEpoch == 0 {
		snapshot, err := authority.Observe(ctx, runtime.JetStream(), cfg.NATS.Cell)
		if err != nil {
			return fmt.Errorf("observe regional authority: %w", err)
		}
		if !snapshot.Ready || snapshot.Reason != "observed" || snapshot.Epoch == 0 || !time.Now().Before(snapshot.ExpiresAt) {
			return errors.New("regional authority lease is not current")
		}
		intent.AuthorityEpoch = snapshot.Epoch
	}
	fingerprint, err := intent.Fingerprint()
	if err != nil {
		return err
	}
	service, err := operatorService(ctx, cfg, runtime, true)
	if err != nil {
		return err
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
	hostReader, err := host.NewReader(ctx, host.ReaderConfig{Cell: cfg.NATS.Cell, JS: runtime.JetStream(), StateReplicas: cfg.NATS.Replicas, HostMutations: reader})
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
	Record delivery.ArtifactRecord `json:"record"`
	Error  string                  `json:"error,omitempty"`
}
