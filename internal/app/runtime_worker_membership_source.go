package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"io"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func runRuntimeWorkerMembershipSource(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	if len(args) != 0 {
		return errors.New("runtime-worker-membership-source accepts no arguments")
	}
	uid, gid, err := controllerServiceIdentity()
	if err != nil {
		return err
	}
	if os.Geteuid() != int(uid) || os.Getegid() != int(gid) {
		return errors.New("worker membership source requires the controller service account")
	}
	wire, err := io.ReadAll(io.LimitReader(input, (128<<10)+1))
	if err != nil || len(wire) == 0 || len(wire) > 128<<10 {
		return errors.New("worker membership query is missing or oversized")
	}
	var query hostenroll.WorkerMembershipQuery
	if err := json.Unmarshal(wire, &query, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	cfg, err := LoadConfig(controllerConfigDirectory + "/" + controllerConfigFilename)
	if err != nil {
		return err
	}
	gate, _, err := acceptedControllerAdmissionGate(cfg, bootstrapstart.NewMarkerStore(), controllerClockCheck(controllerBrokerClockProbe()))
	if err != nil {
		return err
	}
	if _, err := gate.AdmitRestartLocal(ctx); err != nil {
		return err
	}
	key, err := readPrivateKey(cfg.Controller.ResponseKeyFile)
	if err != nil {
		return err
	}
	defer clear(key)
	cfg.NATS.Embedded, cfg.NATS.ClientRole = nil, "controller"
	runtime, err := natscell.Start(ctx, cfg.NATS)
	if err != nil {
		return err
	}
	defer runtime.Close()
	mutations, err := authority.OpenReader(ctx, runtime.JetStream(), cfg.NATS.Cell)
	if err != nil {
		return err
	}
	hosts, err := host.NewReader(ctx, host.ReaderConfig{Cell: cfg.NATS.Cell, Conn: runtime.Conn(), JS: runtime.JetStream(), StateReplicas: cfg.NATS.Replicas, HostMutations: mutations})
	if err != nil {
		return err
	}
	grants, err := hostenroll.OpenGrantStore(ctx, runtime.JetStream(), cfg.NATS.Replicas)
	if err != nil {
		return err
	}
	source, err := hostenroll.NewWorkerMembershipSource(ctx, mutations, hosts, grants, runtime.JetStream(), cfg.NATS.Cell, key.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	snapshot, err := source.Read(ctx, query)
	if err != nil {
		return err
	}
	wire, err = protocol.EncodeJSON(snapshot)
	if err != nil || len(wire) > 128<<10 {
		return errors.New("worker membership source result is oversized")
	}
	_, err = output.Write(wire)
	return err
}
