// Package testorigin is a separate test executable. Its ordinary test run has
// no fixture effects; existing consumer tests must explicitly launch the child.
package testorigin

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

const fixtureCommand = "test-origin-capacity"
const fixtureInputLimit = 16 << 20
const fixtureOutputLimit = 256 << 10

// The later external runner owns overlay, namespace and authenticated custody.
// These bytes are test inputs, never a grant to create namespaces or use OCI.
// *_test.go helpers cannot be imported: the consumer launches this measured ELF
// with fixtureCommand, writes one request to stdin, closes stdin and retains the
// original exit status plus the single bounded reply. No request key is secret
// evidence and no reply is production installed-custody or IPC qualification.
type fixtureRequest struct {
	SchemaVersion    int                          `json:"schemaVersion"`
	ControllerConfig []byte                       `json:"controllerConfig"`
	OCI              []byte                       `json:"oci"`
	NATS             []byte                       `json:"nats"`
	Foundation       region.RetainedFoundation    `json:"foundation"`
	Child            rootoci.PoolChildExpectation `json:"child"`
}

type fixtureReply struct {
	SchemaVersion int                    `json:"schemaVersion"`
	Status        string                 `json:"status"`
	Stage         string                 `json:"stage"`
	Admission     *admissionEvidence     `json:"admission,omitzero"`
	OCI           *ociEvidence           `json:"oci,omitzero"`
	NATS          *natsEvidence          `json:"nats,omitzero"`
	Child         *rootoci.PoolChildView `json:"child,omitzero"`
}

func TestMain(m *testing.M) {
	if len(os.Args) != 2 {
		os.Exit(m.Run())
	}
	switch os.Args[1] {
	case "bootstrap-credential-check", "bootstrap-admit-initial", "bootstrap-admit-restart":
		// Importing app excludes app's _test.go TestMain and its clock override.
		if err := app.Run(context.Background(), os.Args[1:], io.Discard); err != nil {
			// SDK errors can carry response bodies; never echo them into evidence.
			os.Exit(1)
		}
		os.Exit(0)
	case materialProducerCommand:
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
		code := runMaterialProducer(ctx, os.Stdin, os.Stdout)
		cancel()
		stop()
		os.Exit(code)
	case natsWorldCommand:
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
		code := runNATSWorldChild(ctx, os.Stdin, os.Stdout)
		cancel()
		stop()
		os.Exit(code)
	case fixtureCommand:
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
		reply, err := runFixture(ctx, os.Stdin)
		cancel()
		stop()
		wire, encodeErr := json.Marshal(reply)
		if encodeErr != nil || len(wire) > fixtureOutputLimit {
			os.Exit(1)
		}
		wire = append(wire, '\n')
		if n, writeErr := os.Stdout.Write(wire); writeErr != nil || n != len(wire) || err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	default:
		os.Exit(m.Run())
	}
}

func runFixture(ctx context.Context, input io.Reader) (reply fixtureReply, err error) {
	reply = fixtureReply{SchemaVersion: 1, Status: "failed", Stage: "request"}
	if closer, ok := input.(io.Closer); ok {
		stop := context.AfterFunc(ctx, func() { _ = closer.Close() })
		defer stop()
	}
	// Clear decoded secret-bearing protocol input before returning either path.
	var request fixtureRequest
	defer func() {
		clear(request.ControllerConfig)
		clear(request.OCI)
		clear(request.NATS)
	}()
	wire, err := io.ReadAll(io.LimitReader(input, fixtureInputLimit+1))
	defer clear(wire)
	if err != nil {
		return reply, err
	}
	if len(wire) == 0 || len(wire) > fixtureInputLimit ||
		protocol.DecodeStrict(wire, &request, fixtureInputLimit) != nil || request.SchemaVersion != 1 ||
		len(request.ControllerConfig) == 0 || len(request.ControllerConfig) > bootstrap.MaxControllerConfigBytes ||
		len(request.OCI) == 0 || len(request.NATS) == 0 || os.Geteuid() != 0 {
		return reply, errors.New("invalid test-origin request or root identity")
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, set := os.LookupEnv(name); set {
			return reply, errors.New("OCI secret-unsafe environment is present")
		}
	}
	if err := bindFixtureNATS(request.ControllerConfig, request.NATS); err != nil {
		return reply, err
	}
	reply.Stage = "oci"
	oci, err := startOCIWorld(ctx, request.OCI)
	if err != nil {
		return reply, err
	}
	defer func() {
		if closeErr := oci.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
			reply.Status, reply.Stage = "failed", "oci-close"
			reply.Child = nil
		}
	}()
	reply.Stage = "original-foundation-producer"
	if err := provisionFoundation(ctx, oci, request.Foundation); err != nil {
		return reply, err
	}
	reply.Stage = "nats"
	nats, err := startNATSWorld(ctx, request.NATS)
	if err != nil {
		return reply, err
	}
	defer func() {
		if closeErr := nats.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
			reply.Status, reply.Stage = "failed", "nats-close"
			reply.Child = nil
		}
	}()
	material := nats.Material()
	materialErr := validateOCIVaultMaterial(request.OCI, material)
	for _, entry := range material {
		clear(entry.Contents)
	}
	if materialErr != nil {
		reply.Stage = "vault-material-binding"
		return reply, materialErr
	}
	reply.Stage = "production-admission-and-capacity"
	admission, child, err := admitAndAdvance(ctx, request.ControllerConfig, request.Child)
	if err != nil {
		return reply, err
	}
	reply.Stage = "protocol-evidence"
	ociEvidence, err := oci.Evidence()
	if err != nil {
		return reply, err
	}
	natsEvidence, err := nats.Evidence()
	if err != nil {
		return reply, err
	}
	if err := ctx.Err(); err != nil {
		return reply, err
	}
	reply.Admission, reply.Child = &admission, &child
	reply.OCI, reply.NATS = &ociEvidence, &natsEvidence
	reply.Status, reply.Stage = "test-origin-child-advanced", "complete"
	return reply, nil
}

func bindFixtureNATS(controllerWire, natsInput []byte) error {
	var cfg app.Config
	var wire natsWire
	defer func() {
		for index := range wire.Material {
			clear(wire.Material[index].Contents)
		}
	}()
	if protocol.DecodeStrict(controllerWire, &cfg, bootstrap.MaxControllerConfigBytes) != nil ||
		cfg.Version != app.ConfigVersion || protocol.DecodeStrict(natsInput, &wire, natsWorldInputLimit) != nil {
		return errors.New("invalid controller or NATS binding input")
	}
	if err := wire.validate(); err != nil {
		return err
	}
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return err
	}
	if wire.DeploymentID != baked.Identity.DeploymentID || cfg.Controller.CandidateID != wire.CandidateID ||
		cfg.Controller.BrokerTicketKeyFile != wire.TicketKeyFile {
		return errors.New("NATS authority differs from exact controller admission inputs")
	}
	matches := 0
	for _, broker := range wire.Brokers {
		if reflect.DeepEqual(cfg.NATS, broker) {
			matches++
		}
	}
	if matches != 1 {
		return errors.New("controller NATS configuration is not one exact fixture broker")
	}
	return nil
}
