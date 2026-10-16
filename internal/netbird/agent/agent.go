// Package agent is the privileged local worker for leader-signed NetBird steps.
// The sandboxed host runtime only relays artifacts and signed commands.
package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const StepLifetime = 30 * time.Second

const StateRoot = "/var/lib/terrascale-netbird-agent"

type Config struct {
	Cell, Node, Directory string
	// StateDirectory is an isolated private directory override for fixtures.
	// Production uses StateRoot/<cell>/<node>, outside host writable mounts.
	StateDirectory string
	Controller     ed25519.PublicKey
	spool          *spool
}

type ledger struct {
	Generation                 uint64 `json:"generation"`
	Epoch                      uint64 `json:"epoch"`
	ActionID                   string `json:"action_id"`
	Transaction                string `json:"transaction,omitempty"`
	Action                     string `json:"action,omitempty"`
	Error                      string `json:"error,omitempty"`
	TargetHash                 string `json:"target_hash,omitempty"`
	InstalledTargetHash        string `json:"installed_target_hash,omitempty"`
	AppliedTargetHash          string `json:"applied_target_hash,omitempty"`
	PreviousAppliedTargetHash  string `json:"previous_applied_target_hash,omitempty"`
	InstallProgress            string `json:"install_progress,omitempty"`
	PreviousManagedTransaction string `json:"previous_managed_transaction,omitempty"`
}

func (last ledger) accepts(command network.Command, step protocol.Envelope) bool {
	if step.Epoch < last.Epoch || step.Generation < last.Generation ||
		step.Generation == last.Generation && last.Transaction != "" && command.Transaction != last.Transaction {
		return false
	}
	if command.Transaction == last.Transaction && actionRank(command.Action) < actionRank(last.Action) {
		return false
	}
	if command.Transaction == last.Transaction && last.TargetHash != "" && network.Hash(command.Target) != last.TargetHash {
		return false
	}
	if command.Action == "confirm" && (last.InstalledTargetHash == "" || last.InstalledTargetHash != network.Hash(command.Target)) {
		return false
	}
	return command.ID != last.ActionID || last.Error != "" && command.Action != "install"
}

// Private authority state must never share the relay's writable spool. The
// service gives this tree its own StateDirectory and hides it from the host.
func stateDirectory(cfg Config) (string, error) {
	directory := cfg.StateDirectory
	if directory == "" {
		for _, part := range []string{cfg.Cell, cfg.Node} {
			if part == "" || part == "." || part == ".." || filepath.Base(part) != part {
				return "", errors.New("invalid NetBird worker identity")
			}
		}
		directory = filepath.Join(StateRoot, cfg.Cell, cfg.Node)
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		!filepath.IsAbs(cfg.Directory) || filepath.Clean(cfg.Directory) != cfg.Directory ||
		strings.HasPrefix(directory+"/", cfg.Directory+"/") || strings.HasPrefix(cfg.Directory+"/", directory+"/") {
		return "", errors.New("NetBird authority state must be separate from the relay spool")
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(directory, "/"), "/") {
		current = filepath.Join(current, part)
		if err := os.Mkdir(current, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", err
		}
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() {
			return "", errors.New("NetBird authority state must not traverse symlinks")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0 ||
			info.Mode().Perm()&0022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0) ||
			current == directory && (stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0700) {
			return "", errors.New("NetBird authority state must be privately owned by the worker")
		}
	}
	return directory, nil
}

func loadLedger(directory string) (ledger, error) {
	fd, err := syscall.Open(filepath.Join(directory, "ledger.json"), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return ledger{}, nil
	}
	if err != nil {
		return ledger{}, err
	}
	file := os.NewFile(uintptr(fd), "NetBird authority ledger")
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return ledger{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 || !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return ledger{}, errors.New("unsafe NetBird authority ledger")
	}
	wire, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(wire) > 4096 {
		return ledger{}, errors.New("cannot read NetBird authority ledger")
	}
	var last ledger
	err = json.Unmarshal(wire, &last, json.RejectUnknownMembers(true))
	if err == nil && (last.ActionID != "" && !entityid.Valid(last.ActionID) ||
		last.Transaction != "" && !entityid.Valid(last.Transaction) ||
		last.PreviousManagedTransaction != "" && !entityid.Valid(last.PreviousManagedTransaction)) {
		err = errors.New("invalid NetBird ledger identity")
	}
	return last, err
}

func saveLedger(directory string, last ledger) error {
	wire, err := json.Marshal(last)
	if err != nil {
		return err
	}
	return Write(directory, "ledger.json", wire)
}

// Write persists a spool file before making it visible to the worker.
func Write(directory, name string, wire []byte) error {
	if !spoolName(name) {
		return errors.New("invalid NetBird spool filename")
	}
	spool, err := openSpool(directory, true)
	if err != nil {
		return err
	}
	defer spool.close()
	return spool.write(name, wire)
}

func read(directory, name string, limit int64) ([]byte, error) {
	spool, err := openSpool(directory, false)
	if err != nil {
		return nil, err
	}
	defer spool.close()
	return spool.read(name, limit)
}

func ReadStatus(directory string) (network.Status, error) {
	wire, err := read(directory, "status.json", 4096)
	if err != nil {
		return network.Status{}, err
	}
	var status network.Status
	err = json.Unmarshal(wire, &status, json.RejectUnknownMembers(true))
	if err == nil {
		err = status.Validate()
	}
	return status, err
}

func Verify(cfg Config, wire []byte) (network.Command, protocol.Envelope, error) {
	var step protocol.Envelope
	if err := protocol.DecodeStrict(wire, &step, 16<<10); err != nil {
		return network.Command{}, step, err
	}
	if err := protocol.VerifyEnvelope(step, protocol.EnvelopeScope{Region: cfg.Cell, Kind: "netbird.step", Actor: cfg.Node,
		OperationID: step.OperationID, Epoch: step.Epoch, Generation: step.Generation}, cfg.Controller, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: StepLifetime, ClockSkew: time.Second}); err != nil {
		return network.Command{}, step, err
	}
	var command network.Command
	if err := json.Unmarshal(step.Payload, &command, json.RejectUnknownMembers(true)); err != nil {
		return command, step, err
	}
	if command.ID != step.OperationID || !entityid.Valid(command.Transaction) || command.ID != network.CommandID(command.Transaction, command.Action) || step.Epoch == 0 || command.Generation == 0 || command.Generation != step.Generation {
		return command, step, errors.New("invalid NetBird command binding")
	}
	if command.Action != "install" && command.Action != "confirm" && command.Action != "rollback" {
		return command, step, errors.New("invalid NetBird action")
	}
	if err := client.ValidatePin(command.Target.Pin); err != nil {
		return command, step, err
	}
	if err := command.Target.Enrollment.Validate(); err != nil {
		return command, step, err
	}
	return command, step, nil
}

// Relay stages only bytes named in the verified cell pin. It never executes
// an archive or interprets a controller-supplied filesystem path.
func Relay(ctx context.Context, cfg Config, wire []byte, fetch func(context.Context, string, io.Writer) error) error {
	command, _, err := Verify(cfg, wire)
	if err != nil {
		return err
	}
	spool, err := openSpool(cfg.Directory, true)
	if err != nil {
		return err
	}
	defer spool.close()
	if command.Action == "install" {
		pin, err := command.Target.Pin.Archive(runtime.GOARCH)
		if err != nil {
			return err
		}
		destination := "binary-" + pin.BinarySHA256
		if client.VerifyBinary(spool.path(destination), pin.BinarySHA256, runtime.GOARCH) != nil {
			file, temporary, err := spool.temporary()
			if err != nil {
				return err
			}
			defer spool.remove(temporary)
			err = fetch(ctx, pin.BinarySHA256, file)
			if err == nil {
				err = file.Sync()
			}
			err = errors.Join(err, file.Close())
			if err != nil {
				return err
			}
			if err := client.VerifyBinary(spool.path(temporary), pin.BinarySHA256, runtime.GOARCH); err != nil {
				return err
			}
			if err := spool.rename(temporary, destination); err != nil {
				return err
			}
		} else if err := spool.sync(destination, client.MaxBinaryBytes); err != nil {
			// Cached bytes may predate durability checks or an interrupted rename sync.
			return err
		}
	}
	// The transfer can exceed the signed step's short lifetime. The next
	// exchange supplies a fresh signature; it reuses the verified artifact.
	if _, _, err := Verify(cfg, wire); err != nil {
		return err
	}
	return spool.write("step.json", wire)
}

func Run(ctx context.Context, cfg Config) error {
	if os.Geteuid() != 0 {
		return errors.New("NetBird agent must run as root")
	}
	directory, err := stateDirectory(cfg)
	if err != nil {
		return err
	}
	cfg.StateDirectory = directory
	last, err := loadLedger(directory)
	if err != nil {
		return err
	}
	cfg.spool, err = openSpool(cfg.Directory, true)
	if err != nil {
		return err
	}
	defer cfg.spool.close()
	for ctx.Err() == nil {
		if wire, err := cfg.spool.read("step.json", 16<<10); err == nil {
			if err := applyStep(ctx, cfg, &last, wire, func(ctx context.Context, command network.Command) error {
				switch command.Action {
				case "install":
					pin, err := command.Target.Pin.Archive(runtime.GOARCH)
					if err != nil {
						return err
					}
					result, err := client.InstallManaged(ctx, command.Target.Pin, command.Target.Enrollment, client.ManagedOptions{
						BinaryPath: cfg.spool.path("binary-" + pin.BinarySHA256), TransactionID: command.Transaction,
						Prepare: func(previous client.ManagedResult) error {
							return prepareInstall(cfg, &last, command.Transaction, previous)
						}})
					if result.TransactionID == command.Transaction {
						last.InstallProgress = "journaled"
					}
					return err
				case "confirm":
					return client.ConfirmManaged(ctx, command.Transaction)
				case "rollback":
					return client.RollbackManagedForWorker(ctx, command.Transaction, last.rollbackProof())
				}
				return errors.New("invalid NetBird action")
			}); err != nil {
				return err
			}
		}
		status := network.Status{ActionID: last.ActionID, Error: last.Error, AppliedTargetHash: last.AppliedTargetHash}
		// Reading the managed journal may recover an interrupted rollback.
		// Observe the executable and daemon only after that recovery finishes.
		if current, err := client.ManagedStatus(ctx); err == nil {
			if current.Pending {
				status.Pending = current.TransactionID
			}
		} else {
			status.Error = "cannot read managed NetBird transaction"
		}
		status.Missing = executableMissing()
		if local, err := netbird.Status(ctx); err == nil {
			status.Version = local.Version
			status.Connected = local.State == "Connected" && local.Management.Connected && local.Signal.Connected && local.Management.URL == netbird.DefaultManagementURL
			if prefix, err := netip.ParsePrefix(local.IP); err == nil {
				status.IP = prefix.Addr().String()
			}
			status.DNS = local.FQDN
		} else if !status.Missing && status.Error == "" {
			status.Error = "cannot query running NetBird status"
		}
		status.ObservedAt = time.Now().UTC()
		wire, _ := json.Marshal(status)
		if err := cfg.spool.write("status.json", wire); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return ctx.Err()
}

func executableMissing() bool {
	_, err := exec.LookPath("netbird")
	if !errors.Is(err, exec.ErrNotFound) {
		return false
	}
	// LookPath also returns ErrNotFound for a present, non-executable file.
	// Permissions and broken paths are failures, not missing-client bootstrap.
	for _, directory := range filepath.SplitList(os.Getenv("PATH")) {
		if _, err := os.Lstat(filepath.Join(directory, "netbird")); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

func prepareInstall(cfg Config, last *ledger, transaction string, previous client.ManagedResult) error {
	if previous.TransactionID == transaction {
		last.InstallProgress = "journaled"
	} else if previous.Pending {
		// Install rejects someone else's pending mutation without effects.
		return nil
	} else if last.InstallProgress == "unstarted" {
		last.InstallProgress, last.PreviousManagedTransaction = "prepared", previous.TransactionID
	} else if last.InstallProgress != "prepared" || last.PreviousManagedTransaction != previous.TransactionID {
		return errors.New("managed NetBird journal changed since worker preparation")
	}
	return saveLedger(cfg.StateDirectory, *last)
}

func (last ledger) rollbackProof() client.ManagedRollbackProof {
	return client.ManagedRollbackProof{InstallStarted: last.InstallProgress != "unstarted",
		InstallCommitted:      last.InstallProgress != "unstarted" && last.InstallProgress != "prepared" || last.InstalledTargetHash != "",
		PreviousTransactionID: last.PreviousManagedTransaction}
}

func applyStep(ctx context.Context, cfg Config, last *ledger, wire []byte, perform func(context.Context, network.Command) error) error {
	command, step, err := Verify(cfg, wire)
	if err != nil || !last.accepts(command, step) {
		return nil
	}
	if command.Transaction != last.Transaction {
		last.PreviousAppliedTargetHash = last.AppliedTargetHash
		last.InstalledTargetHash = ""
		last.InstallProgress, last.PreviousManagedTransaction = "unstarted", ""
	}
	// Authority is durable before effects, and is never read from the relay.
	last.Epoch, last.Generation = step.Epoch, step.Generation
	last.Transaction, last.Action = command.Transaction, command.Action
	last.TargetHash = network.Hash(command.Target)
	if err := saveLedger(cfg.StateDirectory, *last); err != nil {
		return err
	}
	actionErr := perform(ctx, command)
	last.ActionID, last.Error = command.ID, ""
	if actionErr != nil {
		last.Error = fmt.Sprint(actionErr)
	} else {
		switch command.Action {
		case "install":
			last.InstalledTargetHash = last.TargetHash
		case "confirm":
			last.AppliedTargetHash = last.InstalledTargetHash
		case "rollback":
			last.AppliedTargetHash = last.PreviousAppliedTargetHash
			last.InstalledTargetHash = ""
		}
	}
	if err := saveLedger(cfg.StateDirectory, *last); err != nil {
		return err
	}
	// This copy is diagnostic output only. A compromised relay may delete or
	// rewrite it without changing the worker's authority or target identity.
	result, _ := json.Marshal(last)
	if cfg.spool != nil {
		return cfg.spool.write("result.json", result)
	}
	return Write(cfg.Directory, "result.json", result)
}

func actionRank(action string) int {
	switch action {
	case "install":
		return 1
	case "confirm":
		return 2
	case "rollback":
		return 3
	}
	return 0
}
