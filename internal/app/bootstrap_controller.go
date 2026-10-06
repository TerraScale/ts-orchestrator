package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const controllerServiceUser = "terrascale-orchestrator"
const controllerAdmissionTimeout = 240 * time.Second

var controllerBakedInputsPresent = bootstrapstart.BakedInputsPresent
var controllerBootstrapProduction = superviseControllerRestart
var controllerBootstrapCommand = bootstrapController

func admitControllerBootstrap(ctx context.Context, cfg Config, clockCheck func() error) error {
	present, err := controllerBakedInputsPresent()
	if err != nil {
		return fmt.Errorf("inspect baked controller bootstrap inputs: %w", err)
	}
	if !present {
		if cfg.NATS.Lab {
			return nil
		}
		return errors.New("production controller requires baked bootstrap inputs")
	}
	if clockCheck == nil {
		return errors.New("production controller NTP clock check is unavailable")
	}
	if err := clockCheck(); err != nil {
		return fmt.Errorf("production controller startup NTP clock health: %w", err)
	}
	return controllerBootstrapProduction(ctx, cfg)
}

func bootstrapController(ctx context.Context, cfg Config) error {
	if os.Geteuid() != 0 {
		return errors.New("bootstrap-controller requires root")
	}
	present, err := controllerBakedInputsPresent()
	if err != nil {
		return fmt.Errorf("inspect baked controller bootstrap inputs: %w", err)
	}
	if !present {
		if cfg.NATS.Lab {
			return nil
		}
		return errors.New("production controller requires baked bootstrap inputs")
	}
	if err := controllerClockCheck(controllerBrokerClockProbe())(); err != nil {
		return fmt.Errorf("production controller startup NTP clock health: %w", err)
	}
	present, err = acceptedControllerInstallPresent(bootstrapstart.NewMarkerStore().Read)
	if err != nil {
		return err
	}
	if present {
		// The service-account controller performs full restart admission.
		return nil
	}
	return superviseControllerAdmission(ctx, cfg, "bootstrap-admit-initial", "/proc/self/exe")
}

func acceptedControllerInstallPresent(read func() (bootstrapstart.AcceptedInstall, error)) (bool, error) {
	if read == nil {
		return false, errors.New("accepted controller install reader is unavailable")
	}
	if _, err := read(); err == nil {
		return true, nil
	} else if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else {
		return false, fmt.Errorf("read accepted controller install: %w", err)
	}
}

func superviseControllerRestart(ctx context.Context, cfg Config) error {
	return superviseControllerAdmission(ctx, cfg, "bootstrap-admit-restart", "/proc/self/exe")
}

// superviseControllerAdmission is a process boundary because the OCI SDK's
// synchronous instance-principal retry sleeps do not observe a Go context.
// Killing the child's process group also stops its service-account credential
// grandchild before the caller can continue toward NATS. This uses Linux
// /proc/self/exe and process-group semantics, as does the single-binary image.
func superviseControllerAdmission(ctx context.Context, cfg Config, commandName, executable string) error {
	if commandName != "bootstrap-admit-initial" && commandName != "bootstrap-admit-restart" || executable == "" {
		return errors.New("invalid controller admission child command")
	}
	wire, err := protocol.EncodeJSON(cfg)
	if err != nil || len(wire) == 0 || len(wire) > maxConfigBytes {
		return errors.New("encode bounded controller admission configuration")
	}
	childCtx, cancel := context.WithTimeout(ctx, controllerAdmissionTimeout)
	defer cancel()
	child := exec.CommandContext(childCtx, executable, commandName)
	child.Stdin = bytes.NewReader(wire)
	child.Stdout = io.Discard
	// Admission errors carry no secret values; keep them in the unit journal.
	child.Stderr = os.Stderr
	child.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	child.Cancel = func() error {
		if err := syscall.Kill(-child.Process.Pid, syscall.SIGKILL); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return os.ErrProcessDone
			}
			return err
		}
		return nil
	}
	child.WaitDelay = 5 * time.Second
	err = child.Run()
	if ctxErr := childCtx.Err(); ctxErr != nil {
		return fmt.Errorf("controller admission exceeded its startup deadline: %w", ctxErr)
	}
	if err != nil {
		return fmt.Errorf("controller admission child failed: %w", err)
	}
	return nil
}

func runControllerAdmissionChild(ctx context.Context, commandName string, input io.Reader) error {
	wire, err := io.ReadAll(io.LimitReader(input, maxConfigBytes+1))
	if err != nil || len(wire) == 0 || len(wire) > maxConfigBytes {
		return errors.New("controller admission child configuration is invalid")
	}
	var cfg Config
	if err := protocol.DecodeStrict(wire, &cfg, maxConfigBytes); err != nil {
		return fmt.Errorf("decode controller admission child configuration: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, controllerAdmissionTimeout)
	defer cancel()
	switch commandName {
	case "bootstrap-admit-initial":
		if os.Geteuid() != 0 {
			return errors.New("initial controller admission requires root")
		}
		return admitProductionControllerRoot(ctx, cfg)
	case "bootstrap-admit-restart":
		uid, gid, err := controllerServiceIdentity()
		if err != nil {
			return err
		}
		if os.Geteuid() != int(uid) || os.Getegid() != int(gid) {
			return errors.New("controller restart admission child requires the dedicated service account")
		}
		return admitProductionControllerRestart(ctx, cfg)
	default:
		return errors.New("unknown controller admission child command")
	}
}

func admitProductionControllerRoot(ctx context.Context, cfg Config) error {
	markers := bootstrapstart.NewMarkerStore()
	_, err := markers.Read()
	if err == nil {
		return admitProductionController(ctx, cfg, markers, false)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect accepted bootstrap install: %w", err)
	}
	return admitProductionController(ctx, cfg, markers, true)
}

func admitProductionControllerRestart(ctx context.Context, cfg Config) error {
	return admitProductionController(ctx, cfg, bootstrapstart.NewMarkerStore(), false)
}

func admitProductionController(ctx context.Context, cfg Config, markers bootstrapstart.MarkerStore, initial bool) error {
	loadedWire, err := protocol.EncodeJSON(cfg)
	if err != nil || len(loadedWire) == 0 || len(loadedWire) > bootstrap.MaxControllerConfigBytes {
		return errors.New("loaded controller config is not bounded canonical JSON")
	}
	clockCheck := controllerClockCheck(controllerBrokerClockProbe())
	if err := clockCheck(); err != nil {
		return fmt.Errorf("production controller startup NTP clock health: %w", err)
	}
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return fmt.Errorf("load fixed baked controller bootstrap inputs: %w", err)
	}
	if cfg.NATS.Lab || cfg.NATS.Cell != strings.ToLower(string(baked.Identity.Cell)) {
		return errors.New("controller config does not match baked production cell and mode")
	}
	serviceUID, serviceGID, err := controllerServiceIdentity()
	if err != nil {
		return err
	}
	if !initial && (os.Geteuid() != int(serviceUID) && os.Geteuid() != 0 ||
		os.Geteuid() == int(serviceUID) && os.Getegid() != int(serviceGID)) {
		return errors.New("controller restart admission requires the dedicated service account")
	}
	checker, err := bootstrapstart.NewLiveCredentialChecker(cfg.NATS, serviceUID, serviceGID,
		cfg.Controller.ResponseKeyFile, cfg.Controller.BrokerTicketKeyFile,
		cfg.Controller.HostNATSIssuerSeedFile, cfg.Controller.HostTLSIssuerKeyFile,
		cfg.Controller.HostTLSIssuerCertFile, func() error {
			if _, err := readPrivateKey(cfg.Controller.ResponseKeyFile); err != nil {
				return fmt.Errorf("controller response key: %w", err)
			}
			_, _, err := brokerTicketKeys(cfg)
			return err
		})
	if err != nil {
		return err
	}
	checker.TerraBaseCACertFile = cfg.Controller.TerraBaseCACertFile
	checker.TerraBaseCAKeyFile = cfg.Controller.TerraBaseCAKeyFile
	anchorEnvelope, err := trust.DecodeEnvelope(baked.AnchorWire)
	if err != nil {
		return fmt.Errorf("decode baked controller anchor: %w", err)
	}
	gate := bootstrapstart.Gate{
		Roots: baked.Roots, AnchorWire: baked.AnchorWire, Expected: baked.Identity.AnchorExpectation(),
		LoadedControllerConfigSHA256: controllerSHA256(loadedWire),
		Descriptor:                   bootstrapstart.NewIMDSClient(),
		Credentials:                  checker, Markers: markers,
		ClockCheck: clockCheck,
		SelfUpdate: selfupdate.NewLayout(selfUpdateRoot(cfg.Controller.SelfUpdateRoot)),
	}
	if initial {
		gate.InitialPeerFloor = func(ctx context.Context, marker bootstrapstart.AcceptedInstall,
			state bootstrap.SlotState, now time.Time,
		) error {
			checker, err := bootstrapstart.NewOCIFounderPeerContinuation(baked, marker, serviceUID, serviceGID)
			if err != nil {
				return err
			}
			return checker.Initialize(ctx, marker, state, now)
		}
		floor, err := bootstrapstart.NewServiceFounderSelectionFloorStore(serviceUID)
		if err != nil {
			return err
		}
		gate.InitialFounderFloor = func(ctx context.Context, marker bootstrapstart.AcceptedInstall, now time.Time) error {
			return bootstrapstart.ProvisionInitialFounderFloor(ctx, baked, marker, floor, serviceUID, serviceGID, now, clockCheck)
		}
		if err := clockCheck(); err != nil {
			return fmt.Errorf("production controller startup NTP clock health: %w", err)
		}
		anchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, baked.Roots, gate.Expected,
			time.Now(), bootstrap.BootstrapAnchorTrustPolicy())
		if err != nil {
			return fmt.Errorf("verify current baked controller anchor: %w", err)
		}
		if err := clockCheck(); err != nil {
			return fmt.Errorf("production controller startup NTP clock health: %w", err)
		}
		var vault *bootstrap.Vault
		gate.Instances, gate.Ledgers, vault, err = bootstrapstart.NewCurrentOCIAdmissionClients(anchor, baked.Roots)
		if err != nil {
			return err
		}
		gate.Material, err = bootstrapstart.NewMaterialStore(vault, serviceUID, serviceGID)
		if err != nil {
			return err
		}
		_, err = gate.AdmitInitialWhenReady(ctx)
		return err
	}
	marker, err := markers.Read()
	if err != nil {
		return fmt.Errorf("read accepted controller bootstrap install: %w", err)
	}
	anchor, err := bootstrap.VerifyHistoricalBootstrapAnchor(anchorEnvelope, baked.Roots, gate.Expected,
		marker.AcceptedAt, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return fmt.Errorf("verify accepted baked controller anchor: %w", err)
	}
	if err := clockCheck(); err != nil {
		return fmt.Errorf("production controller startup NTP clock health: %w", err)
	}
	gate.Instances, gate.Ledgers, err = bootstrapstart.NewHistoricalOCIAdmissionClients(anchor, baked.Roots)
	if err != nil {
		return err
	}
	gate.Material, err = bootstrapstart.NewMaterialStore(nil, serviceUID, serviceGID)
	if err != nil {
		return err
	}
	gate.Continuation, err = bootstrapstart.NewOCIFounderInstallContinuation(baked, marker, checker, serviceUID)
	if err != nil {
		return err
	}
	_, err = gate.AdmitRestart(ctx)
	return err
}

func controllerServiceIdentity() (uint32, uint32, error) {
	account, err := user.Lookup(controllerServiceUser)
	if err != nil {
		return 0, 0, fmt.Errorf("look up dedicated controller service account: %w", err)
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		return 0, 0, errors.New("dedicated controller service UID/GID is invalid")
	}
	return uint32(uid), uint32(gid), nil
}
