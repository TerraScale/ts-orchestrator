package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go"
)

func inspection(ctx context.Context, p *process, name string) (swarmruntime.ServiceInspection, error) {
	service, err := swarmruntime.ServiceByName(ctx, p.control, name)
	if err != nil {
		return swarmruntime.ServiceInspection{}, err
	}
	return swarmruntime.InspectService(service)
}

func stored(state, name string) (mesh.Entry, error) {
	data, err := os.ReadFile(filepath.Join(state, "mesh", "desired.json"))
	if err != nil {
		return mesh.Entry{}, err
	}
	entries := map[string]mesh.Entry{}
	if err := protocol.DecodeTolerant(data, &entries, protocol.DefaultMaxJSONBytes); err != nil {
		return mesh.Entry{}, err
	}
	entry := entries[name]
	if entry.Spec == nil {
		return mesh.Entry{}, errors.New("stored declaration is missing")
	}
	return entry, nil
}

func applyDeclaration(ctx context.Context, conn *nats.Conn, state string, spec swarmruntime.ServiceSpec) error {
	before, err := stored(state, spec.Name)
	if err != nil {
		return err
	}
	request, err := protocol.EncodeJSON(mesh.ApplyRequest{Name: spec.Name,
		Entry: mesh.Entry{Generation: max(time.Now().UnixNano(), before.Generation+1), Spec: &spec}})
	if err != nil {
		return err
	}
	response, err := conn.RequestWithContext(ctx, mesh.ApplySubject, request)
	if err != nil {
		return err
	}
	var reply mesh.Reply
	if err := json.Unmarshal(response.Data, &reply); err != nil {
		return err
	}
	if reply.Error != "" {
		return errors.New(reply.Error)
	}
	if reply.Result != "applied" && reply.Result != "unchanged" {
		return fmt.Errorf("declaration was not applied: %+v", reply)
	}
	return nil
}

func upgrade(ctx context.Context, p *process, conn *nats.Conn, state string) error {
	for _, name := range []string{"netbird-server", "boot-peer", "boot-default"} {
		view, err := inspection(ctx, p, name)
		if err != nil {
			return err
		}
		if name == "boot-peer" {
			if view.Spec.Dependencies == nil || !slices.Equal(*view.Spec.Dependencies, []string{"peers"}) {
				return errors.New("explicit peers dependency lost during inspection")
			}
		} else if view.Spec.Dependencies != nil {
			return errors.New("omitted dependency changed during inspection")
		}
		if _, err := view.Spec.SwarmSpec(); err != nil {
			return fmt.Errorf("inspection cannot be reapplied: %w", err)
		}
	}
	view, err := inspection(ctx, p, "netbird-server")
	if err != nil {
		return err
	}
	view.Spec.Regions = []string{"gru"}
	view.Spec.Dependencies = new([]string{})
	if view.Spec.Env["TS_ORCH_NETBIRD_CONFIG_SHA256"] != "existing-config" {
		return errors.New("old declaration lost its current configuration digest")
	}
	if err := applyDeclaration(ctx, conn, state, view.Spec); err != nil {
		return err
	}
	view, err = inspection(ctx, p, "netbird-server")
	if err != nil {
		return err
	}
	if view.Spec.Dependencies == nil || len(*view.Spec.Dependencies) != 0 || view.Spec.Env["TS_ORCH_NETBIRD_CONFIG_SHA256"] != "existing-config" {
		return errors.New("upgrade lost dependencies or the existing configuration digest")
	}
	wire, err := protocol.EncodeJSON(view)
	if err != nil {
		return err
	}
	rolled, changed, err := manager.ServerConfigSpec(wire, []byte("new management configuration"))
	if err != nil || !changed {
		return fmt.Errorf("management configuration roll was not produced: %w", err)
	}
	var spec swarmruntime.ServiceSpec
	if err := protocol.DecodeStrict(rolled, &spec, protocol.DefaultMaxJSONBytes); err != nil {
		return err
	}
	if err := applyDeclaration(ctx, conn, state, spec); err != nil {
		return err
	}
	view, err = inspection(ctx, p, "netbird-server")
	if err != nil {
		return err
	}
	if view.Spec.Dependencies == nil || len(*view.Spec.Dependencies) != 0 || view.Spec.Env["TS_ORCH_NETBIRD_CONFIG_SHA256"] == "existing-config" {
		return errors.New("configuration roll lost empty dependencies or failed to change the digest")
	}
	wire, err = protocol.EncodeJSON(view)
	if err != nil {
		return err
	}
	if _, changed, err := manager.ServerConfigSpec(wire, []byte("new management configuration")); err != nil || changed {
		return errors.New("configuration roll did not settle")
	}
	current, err := stored(state, "netbird-server")
	if err != nil {
		return err
	}
	stripped := current
	spec = *current.Spec
	spec.Dependencies = nil
	stripped.Spec = &spec
	request, err := protocol.EncodeJSON(mesh.ApplyRequest{Name: spec.Name, Entry: stripped})
	if err != nil {
		return err
	}
	response, err := conn.RequestWithContext(ctx, mesh.ApplySubject, request)
	if err != nil {
		return err
	}
	var reply mesh.Reply
	if err := json.Unmarshal(response.Data, &reply); err != nil {
		return err
	}
	if !strings.Contains(reply.Error, "superseded by generation") {
		return fmt.Errorf("stripped equal-generation copy was not refused: %+v", reply)
	}
	after, err := stored(state, "netbird-server")
	if err != nil {
		return err
	}
	a, err := protocol.EncodeJSON(current)
	if err != nil {
		return err
	}
	b, err := protocol.EncodeJSON(after)
	if err != nil {
		return err
	}
	if string(a) != string(b) {
		return errors.New("stripped equal-generation copy changed stored declaration")
	}
	fmt.Println("boot-order: applied upgrade, configuration roll and read-apply preserved empty dependencies; stripped same-generation copy refused")
	return nil
}
