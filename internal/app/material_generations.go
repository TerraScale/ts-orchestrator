package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/generationinstall"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// Material generation install (TS-668): the operator's requests to the
// authority leader. status needs a trusted signer; a change needs the
// signer's can_install_material grant, and a chain must be root-signed.
const (
	materialGenerationKinds         = "material.generation."
	materialGenerationStatusKind    = materialGenerationKinds + "status"
	materialGenerationPublishKind   = materialGenerationKinds + "publish"
	materialGenerationConfigKind    = materialGenerationKinds + "config"
	materialGenerationArmKind       = materialGenerationKinds + "arm"
	maxMaterialGenerationReplyBytes = 64 << 10
)

type materialGenerationRequest struct {
	Chain  []byte `json:"chain,omitempty"`
	Slot   string `json:"slot,omitempty"`
	Config []byte `json:"config,omitempty"`
	Armed  bool   `json:"armed,omitzero"`
}

type materialGenerationReply struct {
	Report *generationinstall.Report `json:"report,omitempty"`
	Error  string                    `json:"error,omitempty"`
}

// materialGenerationTarget is this controller's accepted slot and manifest;
// tests replace it.
var materialGenerationTarget = bootstrapstart.AcceptedGenerationTarget

func serveMaterialGenerations(ctx context.Context, wire []byte, policy signerPolicy, fencer authority.Fencer,
	roots *rootRegistry,
) (generationinstall.Report, error) {
	envelope, actor, err := verifyCellRequest(wire, policy, fencer)
	if err != nil {
		return generationinstall.Report{}, err
	}
	target, err := materialGenerationTarget()
	if err != nil {
		return generationinstall.Report{}, fmt.Errorf("material generations need an accepted production controller: %w", err)
	}
	leader := generationinstall.Leader{KV: roots.kv, Expected: target.Expected, Roots: roots.current,
		Guard: func(ctx context.Context) error { return fencer.Guard(ctx, envelope.Epoch) }}
	if envelope.Kind == materialGenerationStatusKind {
		return leader.Report(ctx)
	}
	if grant, _ := policy.grant(actor); !grant.CanInstallMaterial {
		return generationinstall.Report{}, fmt.Errorf("trusted signer %s may not install material generations (can_install_material)", actor)
	}
	var request materialGenerationRequest
	if err := protocol.DecodeStrict(envelope.Payload, &request, maxRegistrationBytes); err != nil {
		return generationinstall.Report{}, fmt.Errorf("decode %s: %w", envelope.Kind, err)
	}
	var status string
	switch envelope.Kind {
	case materialGenerationPublishKind:
		status, err = leader.Publish(ctx, request.Chain)
	case materialGenerationConfigKind:
		status, err = leader.SetConfig(ctx, request.Slot, request.Config)
	case materialGenerationArmKind:
		status, err = leader.Arm(ctx, request.Slot, request.Armed)
	default:
		err = fmt.Errorf("unknown material generation request %q", envelope.Kind)
	}
	if err != nil {
		return generationinstall.Report{}, err
	}
	slog.Info("material generation request", observability.ComponentKey, "trust", "actor", actor,
		"kind", envelope.Kind, "slot", request.Slot, "status", status)
	report, err := leader.Report(ctx)
	report.Status = status
	return report, err
}

// operatorMaterialGeneration runs ts-orch operator material-generation
// publish|status|arm|disarm. publish sends the chain, then each slot's
// config.
func operatorMaterialGeneration(ctx context.Context, cfg Config, runtime *natscell.Runtime, command, chainPath string,
	configs map[string]string, slot string, output io.Writer,
) error {
	request := func(kind string, payload materialGenerationRequest) (generationinstall.Report, error) {
		encoded, err := protocol.EncodeJSON(payload)
		if err != nil {
			return generationinstall.Report{}, err
		}
		data, err := requestLeader(ctx, cfg, runtime, kind, "material-generation", encoded)
		if err != nil {
			return generationinstall.Report{}, err
		}
		var reply materialGenerationReply
		if err := protocol.DecodeStrict(data, &reply, maxMaterialGenerationReplyBytes); err != nil {
			return generationinstall.Report{}, fmt.Errorf("decode %s reply: %w", kind, err)
		}
		if reply.Error != "" || reply.Report == nil {
			return generationinstall.Report{}, errors.New(reply.Error)
		}
		return *reply.Report, nil
	}
	var report generationinstall.Report
	var err error
	switch command {
	case "status":
		report, err = request(materialGenerationStatusKind, materialGenerationRequest{})
	case "publish":
		if chainPath == "" || slot != "" {
			return errors.New("material-generation publish requires --chain and takes --controller-config SLOT=FILE")
		}
		chain, readErr := readBoundedConfigFile(chainPath)
		if readErr != nil {
			return readErr
		}
		// ponytail: one request carries the whole chain, so about seven
		// generations fit the 64 KiB request bound; send only the new
		// generations once chains grow past it.
		report, err = request(materialGenerationPublishKind, materialGenerationRequest{Chain: chain})
		for _, configSlot := range slices.Sorted(maps.Keys(configs)) {
			if err != nil {
				break
			}
			data, readErr := readBoundedConfigFile(configs[configSlot])
			if readErr != nil {
				return readErr
			}
			report, err = request(materialGenerationConfigKind, materialGenerationRequest{Slot: configSlot, Config: data})
		}
	case "arm", "disarm":
		if slot == "" || chainPath != "" || len(configs) != 0 {
			return fmt.Errorf("material-generation %s requires only --slot", command)
		}
		report, err = request(materialGenerationArmKind, materialGenerationRequest{Slot: slot, Armed: command == "arm"})
	default:
		return fmt.Errorf("unknown material-generation command %q (publish, status, arm, disarm)", command)
	}
	if err != nil {
		return err
	}
	return printJSON(output, report)
}

// controllerConfigFlags collects repeated --controller-config SLOT=FILE.
type controllerConfigFlags map[string]string

func (*controllerConfigFlags) String() string { return "" }

func (flags *controllerConfigFlags) Set(value string) error {
	slot, path, ok := strings.Cut(value, "=")
	if !ok || slot == "" || path == "" {
		return errors.New("--controller-config requires SLOT=FILE")
	}
	if *flags == nil {
		*flags = controllerConfigFlags{}
	}
	if _, duplicate := (*flags)[slot]; duplicate {
		return fmt.Errorf("duplicate --controller-config for %s", slot)
	}
	(*flags)[slot] = path
	return nil
}

// runMaterialGenerationStager stages the cell's published material
// generation for this controller's slot. It is inert until an operator
// publishes a chain, and never stops the controller.
func runMaterialGenerationStager(ctx context.Context, roots *rootRegistry) {
	target, err := materialGenerationTarget()
	if err != nil {
		slog.Warn("material generation stager is off", observability.ComponentKey, "trust", "error", err)
		return
	}
	var vault *bootstrap.Vault
	read := func(ctx context.Context, reference bootstrap.SecretReference) ([]byte, error) {
		if vault == nil {
			region, err := target.Expected.Cell.OCIRegion()
			if err != nil {
				return nil, err
			}
			factory, err := ociclient.InstancePrincipal(region)
			if err != nil {
				return nil, err
			}
			created, err := bootstrap.NewInstancePrincipalVault(target.Expected.Cell, factory.Provider())
			if err != nil {
				return nil, err
			}
			vault = created
		}
		return vault.ReadGenerationSecret(ctx, reference)
	}
	stager := &generationinstall.Stager{KV: roots.kv, Target: target, Roots: roots.current, Read: read,
		Installed: filepath.Join(bootstrapstart.MaterialDirectory, bootstrapstart.MaterialGenerationsFile),
		Spool:     bootstrapstart.GenerationSpoolDirectory}
	stager.Run(ctx)
}
