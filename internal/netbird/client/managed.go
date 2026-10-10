package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird"
)

const (
	managedDirectory = "/var/lib/terrascale-orchestrator/netbird-managed"
	managedBinary    = "/usr/local/bin/netbird"
	rollbackUnit     = "terrascale-netbird-rollback"
	rollbackWindow   = 5 * time.Minute
)

var managedVersionPattern = regexp.MustCompile(`^0\.80\.[0-9]+$`)
var runningVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var errManagedUnitNotEnabled = errors.New("NetBird service is disabled or missing")

func ValidateManagedVersion(version string) error {
	if !managedVersionPattern.MatchString(version) {
		return errors.New("managed NetBird pin must be a 0.80.x release")
	}
	return nil
}

type ManagedOptions struct {
	// BinaryPath is an already staged artifact on nodes without Internet
	// access. It is verified against the pin before any service mutation.
	BinaryPath    string
	TransactionID string
	Bootstrap     bool
	// Prepare records the existing journal under the operation lock before
	// any installation effects, so the worker can prove a failed first attempt.
	Prepare func(ManagedResult) error
}

type ManagedResult struct {
	TransactionID    string    `json:"transaction_id"`
	Bootstrap        bool      `json:"bootstrap,omitempty"`
	Version          string    `json:"version"`
	PreviousVersion  string    `json:"previous_version,omitempty"`
	RollbackDeadline time.Time `json:"rollback_deadline"`
	Pending          bool      `json:"pending"`
	RolledBack       bool      `json:"rolled_back,omitempty"`
}

type managedTransaction struct {
	ManagedResult
	BinarySHA256    string `json:"binary_sha256"`
	PreviousSHA256  string `json:"previous_sha256,omitempty"`
	RollbackSHA256  string `json:"rollback_executable_sha256,omitempty"`
	Architecture    string `json:"architecture"`
	StateBackup     bool   `json:"state_backup,omitempty"`
	RestartRequired bool   `json:"restart_required,omitempty"`
}

var managedStatePaths = []string{netbird.PublicConfigPath, "/var/lib/netbird/config.json", "/etc/systemd/system/netbird.service", "/etc/hosts"}

type managedSavedFile struct {
	Exists bool        `json:"exists"`
	Mode   os.FileMode `json:"mode"`
	SHA256 string      `json:"sha256,omitempty"`
}

type managedSavedState struct {
	Enabled bool                        `json:"enabled"`
	Files   map[string]managedSavedFile `json:"files"`
}

func (m managedClient) backupDirectory(transaction managedTransaction) string {
	return m.path(managedDirectory + "/transactions/" + transaction.TransactionID)
}

func (m managedClient) previousBinary(transaction managedTransaction) string {
	if !transaction.StateBackup {
		return m.path(managedDirectory + "/previous")
	}
	return filepath.Join(m.backupDirectory(transaction), "previous-"+transaction.PreviousSHA256)
}

func readManagedStateFile(path string) ([]byte, managedSavedFile, error) {
	return readManagedStateFileLimit(path, 1<<20)
}

func readManagedStateFileLimit(path string, limit int64) ([]byte, managedSavedFile, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, managedSavedFile{}, nil
	}
	if err != nil {
		return nil, managedSavedFile{}, errors.New("cannot open managed NetBird state snapshot")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > limit {
		return nil, managedSavedFile{}, errors.New("managed NetBird state must be a bounded protected regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, managedSavedFile{}, errors.New("managed NetBird state has an unexpected owner")
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, managedSavedFile{}, errors.New("cannot read bounded managed NetBird state")
	}
	digest := sha256.Sum256(body)
	return body, managedSavedFile{Exists: true, Mode: info.Mode().Perm(), SHA256: hex.EncodeToString(digest[:])}, nil
}

func (m managedClient) backupState(ctx context.Context, transaction managedTransaction) error {
	enabled := true
	if err := m.systemctl(ctx, "is-enabled", "netbird.service"); err != nil {
		if !errors.Is(err, errManagedUnitNotEnabled) {
			return err
		}
		enabled = false
	}
	if _, err := secureManagedDirectory(m.root, managedDirectory+"/transactions/"+transaction.TransactionID, 0700); err != nil {
		return err
	}
	state := managedSavedState{Enabled: enabled, Files: map[string]managedSavedFile{}}
	for _, path := range managedStatePaths {
		body, saved, err := readManagedStateFile(m.path(path))
		if err != nil {
			return err
		}
		state.Files[path] = saved
		if saved.Exists {
			if err := atomicManagedFile(filepath.Join(m.backupDirectory(transaction), filepath.Base(path)), body, 0600); err != nil {
				return err
			}
		}
	}
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicManagedFile(filepath.Join(m.backupDirectory(transaction), "state.json"), body, 0600)
}

func managedHostsLines(body []byte, keepManaged bool) []byte {
	var result []byte
	for line := range strings.SplitAfterSeq(string(body), "\n") {
		_, comment, _ := strings.Cut(line, "#")
		managed := "#"+strings.TrimRight(comment, " \t\r\n") == "# terrascale-netbird-manager"
		if managed == keepManaged {
			result = append(result, line...)
		}
	}
	return result
}

func (m managedClient) restoreState(ctx context.Context, transaction managedTransaction) (bool, error) {
	if !transaction.StateBackup {
		return false, errors.New("legacy NetBird transaction has no enrollment rollback snapshot")
	}
	manifest, info, err := readManagedStateFile(filepath.Join(m.backupDirectory(transaction), "state.json"))
	var state managedSavedState
	if err != nil || !info.Exists || len(manifest) > 16<<10 || json.Unmarshal(manifest, &state, json.RejectUnknownMembers(true)) != nil || len(state.Files) != len(managedStatePaths) {
		return false, errors.New("managed NetBird rollback state is invalid")
	}
	// Verify every snapshot before stopping or mutating the live service.
	bodies := map[string][]byte{}
	for _, path := range managedStatePaths {
		saved, ok := state.Files[path]
		if !ok || saved.Mode.Perm() != saved.Mode || saved.Mode&0022 != 0 {
			return false, errors.New("managed NetBird rollback file metadata is invalid")
		}
		if !saved.Exists {
			continue
		}
		body, copied, err := readManagedStateFile(filepath.Join(m.backupDirectory(transaction), filepath.Base(path)))
		if err != nil || !copied.Exists || copied.SHA256 != saved.SHA256 || !SHA256Pattern.MatchString(saved.SHA256) {
			return false, errors.New("managed NetBird rollback snapshot checksum does not match")
		}
		bodies[path] = body
	}
	_, unit, err := readManagedStateFile(m.path("/etc/systemd/system/netbird.service"))
	if err != nil {
		return false, err
	}
	// A first install may crash after journal commit and before the unit is
	// created. There is then no service to stop or disable.
	if transaction.PreviousSHA256 != "" || unit.Exists {
		if err := m.systemctl(ctx, "stop", "netbird.service"); err != nil {
			return false, err
		}
		if err := m.systemctl(ctx, "disable", "netbird.service"); err != nil {
			return false, err
		}
	}
	for _, path := range managedStatePaths {
		saved := state.Files[path]
		body := bodies[path]
		if path == "/etc/hosts" {
			current, currentInfo, err := readManagedStateFile(m.path(path))
			if err != nil {
				return false, err
			}
			if !currentInfo.Exists && !saved.Exists {
				continue
			}
			// Restore only our manager entry; preserve unrelated edits made
			// while the network rollout was pending.
			body = managedHostsLines(current, false)
			prior := managedHostsLines(bodies[path], true)
			if len(prior) != 0 && len(body) != 0 && body[len(body)-1] != '\n' {
				body = append(body, '\n')
			}
			body = append(body, prior...)
			saved.Exists = true
			if saved.Mode == 0 {
				saved.Mode = currentInfo.Mode
			}
		}
		if saved.Exists {
			if _, err := secureManagedDirectory(m.root, filepath.Dir(path), 0755); err != nil {
				return false, err
			}
			if err := atomicManagedFile(m.path(path), body, saved.Mode); err != nil {
				return false, err
			}
		} else if err := removeManagedFile(m.path(path)); err != nil {
			return false, err
		}
	}
	return state.Enabled, m.systemctl(ctx, "daemon-reload")
}

type managedClient struct {
	root, architecture, executable string
	systemctl                      func(context.Context, ...string) error
	status                         func(context.Context) (netbird.LocalStatus, error)
	enroll                         func(context.Context, netbird.Config) error
}

func managedUnitEnabledResult(output string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("NetBird service state query failed: %w", err)
	}
	var exit *exec.ExitError
	switch strings.TrimSpace(output) {
	case "enabled", "enabled-runtime", "alias", "static", "indirect", "generated":
		if err == nil {
			return nil
		}
	case "disabled", "masked", "masked-runtime", "linked", "linked-runtime":
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return errManagedUnitNotEnabled
		}
	case "not-found":
		if errors.As(err, &exit) && exit.ExitCode() == 4 {
			return errManagedUnitNotEnabled
		}
	}
	return errors.New("cannot determine NetBird service enabled state")
}

func localManagedClient() (managedClient, error) {
	if os.Geteuid() != 0 {
		return managedClient{}, errors.New("managed NetBird operations must run as root")
	}
	return managedClient{root: "/", architecture: runtime.GOARCH, executable: "/proc/self/exe",
		status: netbird.Status, enroll: netbird.Enroll,
		systemctl: func(ctx context.Context, args ...string) error {
			commandCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
			defer cancel()
			cmd := exec.CommandContext(commandCtx, "/usr/bin/systemctl", args...)
			cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/root", "LANG=C"}
			cmd.WaitDelay = time.Second
			query := len(args) == 2 && args[0] == "is-enabled" && args[1] == "netbird.service"
			var output bytes.Buffer
			if query {
				cmd.Stdout = &output
			}
			err := cmd.Run()
			if commandCtx.Err() != nil {
				return fmt.Errorf("NetBird service operation failed: %w", commandCtx.Err())
			}
			if query {
				return managedUnitEnabledResult(output.String(), err)
			}
			if err != nil {
				return errors.New("NetBird service operation failed")
			}
			return nil
		}}, nil
}

func (m managedClient) path(path string) string { return filepath.Join(m.root, path) }

func secureManagedDirectory(root, path string, mode os.FileMode) (string, error) {
	directory, err := directDirectory(root, path, mode, false)
	if err != nil {
		return "", err
	}
	current := root
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
			return "", errors.New("managed NetBird parents must be owned by root without group or other write access")
		}
	}
	if mode == 0700 {
		return directory, os.Chmod(directory, mode)
	}
	return directory, nil
}

func (m managedClient) lock() (*os.File, error) {
	directory, err := secureManagedDirectory(m.root, managedDirectory, 0700)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open(filepath.Join(directory, "managed.lock"), syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("cannot open managed NetBird lock")
	}
	lock := os.NewFile(uintptr(fd), "managed.lock")
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		lock.Close()
		return nil, errors.New("managed NetBird lock must be a private regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		lock.Close()
		return nil, errors.New("managed NetBird lock has an unexpected owner")
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return nil, errors.New("another managed NetBird operation is running")
	}
	return lock, nil
}

func atomicManagedFile(path string, body []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("managed NetBird destination must be a direct regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".netbird-managed-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if _, err = f.Write(body); err != nil {
		return err
	}
	if err = errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncManagedDirectory(filepath.Dir(path))
}

func syncManagedDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func removeManagedFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Retry must sync absence too; an interrupted install may lack its parent.
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		err := syncManagedDirectory(parent)
		if !errors.Is(err, os.ErrNotExist) || filepath.Dir(parent) == parent {
			return err
		}
	}
}

func installManagedBinary(source, destination, digest, architecture string) error {
	if info, err := os.Lstat(destination); err == nil && !info.Mode().IsRegular() {
		return errors.New("managed NetBird destination must be a direct regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(destination), ".netbird-managed-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := copyFile(source, file.Name(), 0600); err != nil {
		return err
	}
	// The spool may change after its first verification. Verify the private
	// copy before making any bytes executable at the live service path.
	if err := VerifyBinary(file.Name(), digest, architecture); err != nil {
		return err
	}
	if err := file.Chmod(0755); err != nil {
		return err
	}
	err = errors.Join(file.Sync(), file.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(file.Name(), destination); err != nil {
		return err
	}
	return syncManagedDirectory(filepath.Dir(destination))
}

func (m managedClient) readTransaction() (managedTransaction, error) {
	path := m.path(managedDirectory + "/pending.json")
	body, info, err := readManagedStateFileLimit(path, 4096)
	if err != nil || info.Exists && info.Mode != 0600 {
		return managedTransaction{}, errors.New("managed NetBird transaction must be a bounded private file")
	}
	if !info.Exists {
		return managedTransaction{}, nil
	}
	var transaction managedTransaction
	if json.Unmarshal(body, &transaction, json.RejectUnknownMembers(true)) != nil ||
		!entityid.Valid(transaction.TransactionID) || !SHA256Pattern.MatchString(transaction.BinarySHA256) ||
		transaction.PreviousSHA256 != "" && !SHA256Pattern.MatchString(transaction.PreviousSHA256) ||
		transaction.RollbackSHA256 != "" && !SHA256Pattern.MatchString(transaction.RollbackSHA256) ||
		transaction.Architecture != "arm64" && transaction.Architecture != "amd64" || transaction.RollbackDeadline.IsZero() {
		return managedTransaction{}, errors.New("managed NetBird transaction is invalid")
	}
	return transaction, nil
}

func (m managedClient) writeTransaction(transaction managedTransaction) error {
	body, err := json.Marshal(transaction)
	if err != nil {
		return err
	}
	return atomicManagedFile(m.path(managedDirectory+"/pending.json"), body, 0600)
}

// ManagedStatus also repairs watchdogs after worker/process restart. The root
// worker calls this on startup and every two seconds, independently of a new
// controller command. Completed journals make duplicate confirmations harmless.
func ManagedStatus(ctx context.Context) (ManagedResult, error) {
	if err := ctx.Err(); err != nil {
		return ManagedResult{}, err
	}
	m, err := localManagedClient()
	if err != nil {
		return ManagedResult{}, err
	}
	transaction, err := m.recover(ctx)
	return transaction.ManagedResult, err
}

func (m managedClient) recover(ctx context.Context) (managedTransaction, error) {
	lock, err := m.lock()
	if err != nil {
		return managedTransaction{}, err
	}
	defer lock.Close()
	transaction, err := m.readTransaction()
	if err != nil {
		return transaction, err
	}
	if !transaction.Pending {
		return transaction, nil
	}
	if !time.Now().Before(transaction.RollbackDeadline) {
		if err := m.finishTransaction(ctx, transaction, true); err != nil {
			return transaction, err
		}
		return m.readTransaction()
	}
	if transaction.RollbackSHA256 == "" {
		if err := m.retainRollbackExecutable(ctx, &transaction); err != nil {
			return transaction, err
		}
		if err := m.armRollback(ctx, transaction); err != nil {
			return transaction, err
		}
		return transaction, m.writeTransaction(transaction)
	}
	if err := m.rollbackExecutableReady(transaction); err != nil {
		return transaction, err
	}
	configured := true
	for suffix, expected := range m.rollbackFiles(transaction) {
		body, info, err := readManagedStateFile(m.path("/etc/systemd/system/" + rollbackUnit + suffix))
		if err != nil || !info.Exists || !bytes.Equal(body, []byte(expected)) {
			configured = false
		}
	}
	if !configured || m.systemctl(ctx, "is-active", "--quiet", rollbackUnit+".timer") != nil {
		return transaction, m.armRollback(ctx, transaction)
	}
	return transaction, nil
}

// RunningVersion reads daemonVersion; an installed replacement CLI does not
// prove that systemd has restarted the running network agent.
func RunningVersion(ctx context.Context) (string, error) {
	status, err := netbird.Status(ctx)
	if err != nil {
		return "", err
	}
	return daemonVersion(status)
}

func daemonVersion(status netbird.LocalStatus) (string, error) {
	version := strings.TrimPrefix(status.Version, "v")
	if !runningVersionPattern.MatchString(version) {
		return "", errors.New("running NetBird daemon returned an invalid version")
	}
	return version, nil
}

const managedService = `[Unit]
Description=NetBird private management network and SSH
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
Environment=NB_FORCE_RELAY=true
Environment=NB_LAZY_CONN=on
ExecStart=/usr/local/bin/netbird service run --config /var/lib/netbird/config.json --log-file console
Restart=always
RestartSec=10s
TimeoutStopSec=30s
StateDirectory=netbird
StateDirectoryMode=0700
KillMode=process
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`

func managedUnitSettings(body string) string {
	var settings strings.Builder
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		settings.WriteString(line)
		settings.WriteByte('\n')
	}
	return settings.String()
}

func (m managedClient) configure(ctx context.Context, cfg netbird.Config) error {
	for _, path := range []string{"/usr/local/bin", "/etc/terrascale-orchestrator", "/etc/systemd/system"} {
		if _, err := secureManagedDirectory(m.root, path, 0755); err != nil {
			return err
		}
	}
	if _, err := secureManagedDirectory(m.root, "/var/lib/netbird", 0700); err != nil {
		return err
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err = atomicManagedFile(m.path(netbird.PublicConfigPath), body, 0644); err != nil {
		return err
	}
	return atomicManagedFile(m.path("/etc/systemd/system/netbird.service"), []byte(managedService), 0644)
}

func (m managedClient) rollbackFiles(transaction managedTransaction) map[string]string {
	service := fmt.Sprintf("[Unit]\nDescription=Rollback unconfirmed NetBird update\nStartLimitIntervalSec=0\nConditionPathExists=%s/pending.json\n\n[Service]\nType=oneshot\nExecStart=\"%s\" netbird agent rollback --transaction %s\nRestart=on-failure\nRestartSec=5s\n", managedDirectory, m.rollbackExecutable(transaction), transaction.TransactionID)
	trigger := transaction.RollbackDeadline.UTC().Truncate(time.Second)
	if trigger.Before(transaction.RollbackDeadline) {
		trigger = trigger.Add(time.Second)
	}
	timer := fmt.Sprintf("[Unit]\nDescription=Rollback deadline for managed NetBird\n\n[Timer]\nOnCalendar=%s\nAccuracySec=1s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n", trigger.Format("2006-01-02 15:04:05 UTC"))
	return map[string]string{".service": service, ".timer": timer}
}

func (m managedClient) armRollback(ctx context.Context, transaction managedTransaction) error {
	if err := m.rollbackExecutableReady(transaction); err != nil {
		return err
	}
	if err := verifyBinaryLimit(m.rollbackExecutable(transaction), transaction.RollbackSHA256, transaction.Architecture, maxRollbackExecutableBytes); err != nil {
		return err
	}
	if _, err := secureManagedDirectory(m.root, "/etc/systemd/system", 0755); err != nil {
		return err
	}
	for suffix, body := range m.rollbackFiles(transaction) {
		if err := atomicManagedFile(m.path("/etc/systemd/system/"+rollbackUnit+suffix), []byte(body), 0644); err != nil {
			return err
		}
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", rollbackUnit + ".timer"}, {"restart", rollbackUnit + ".timer"}} {
		if err := m.systemctl(ctx, args...); err != nil {
			return err
		}
	}
	return nil
}

// InstallManaged runs on the target node after its controller drains it and
// verifies a second access path. The old binary remains until confirmation;
// an independent systemd timer rolls back if the controller cannot reconnect.
func InstallManaged(ctx context.Context, pin Pin, cfg netbird.Config, options ManagedOptions) (ManagedResult, error) {
	m, err := localManagedClient()
	if err != nil {
		return ManagedResult{}, err
	}
	return m.install(ctx, pin, cfg, options)
}

func (m managedClient) install(ctx context.Context, pin Pin, cfg netbird.Config, options ManagedOptions) (ManagedResult, error) {
	if err := ctx.Err(); err != nil {
		return ManagedResult{}, err
	}
	if err := ValidatePin(pin); err != nil {
		return ManagedResult{}, err
	}
	if err := ValidateManagedVersion(pin.Version); err != nil {
		return ManagedResult{}, err
	}
	if err := cfg.Validate(); err != nil {
		return ManagedResult{}, err
	}
	if options.TransactionID == "" {
		options.TransactionID = entityid.New()
	}
	if !entityid.Valid(options.TransactionID) {
		return ManagedResult{}, errors.New("invalid managed NetBird transaction identity")
	}
	lock, err := m.lock()
	if err != nil {
		return ManagedResult{}, err
	}
	defer lock.Close()
	archive, err := pin.Archive(m.architecture)
	if err != nil {
		return ManagedResult{}, err
	}
	transaction, err := m.readTransaction()
	if err != nil {
		return ManagedResult{}, err
	}
	if !transaction.Pending && transaction.TransactionID != options.TransactionID {
		if err := checkBootstrapPublication(filepath.Dir(m.path(netbird.PublicConfigPath))); err != nil {
			return ManagedResult{}, err
		}
		if err := m.pruneTransactions(transaction); err != nil {
			return ManagedResult{}, err
		}
	}
	if options.Prepare != nil {
		if err := options.Prepare(transaction.ManagedResult); err != nil {
			return ManagedResult{}, err
		}
	}
	if transaction.TransactionID == options.TransactionID && !transaction.Pending {
		if transaction.BinarySHA256 != archive.BinarySHA256 || transaction.Architecture != m.architecture || transaction.Bootstrap != options.Bootstrap {
			return transaction.ManagedResult, errors.New("managed NetBird transaction pin does not match")
		}
		if transaction.RolledBack {
			return transaction.ManagedResult, errors.New("managed NetBird transaction was rolled back")
		}
		return transaction.ManagedResult, nil
	}
	if transaction.Pending && (transaction.TransactionID != options.TransactionID || transaction.Bootstrap != options.Bootstrap || transaction.BinarySHA256 != archive.BinarySHA256 || transaction.Version != pin.Version) {
		return transaction.ManagedResult, errors.New("another managed NetBird transaction is pending")
	}
	if transaction.Pending && !time.Now().Before(transaction.RollbackDeadline) {
		return transaction.ManagedResult, errors.New("managed NetBird rollback deadline has expired")
	}
	resuming := transaction.Pending
	if !resuming {
		transaction = managedTransaction{ManagedResult: ManagedResult{TransactionID: options.TransactionID, Bootstrap: options.Bootstrap,
			Version: pin.Version, Pending: true, RollbackDeadline: time.Now().Add(rollbackWindow)},
			BinarySHA256: archive.BinarySHA256, Architecture: m.architecture, StateBackup: true}
	}
	// Cumulative command timeouts must not hold the lock past local recovery.
	ctx, cancel := context.WithDeadline(ctx, transaction.RollbackDeadline)
	defer cancel()
	work, err := os.MkdirTemp(m.path(managedDirectory), ".install-")
	if err != nil {
		return ManagedResult{}, err
	}
	defer os.RemoveAll(work)
	binary := options.BinaryPath
	if binary == "" {
		binary = filepath.Join(work, "netbird")
		if err = Fetch(ctx, pin, m.architecture, binary, "", nil); err != nil {
			return ManagedResult{}, err
		}
	}
	if err = VerifyBinary(binary, archive.BinarySHA256, m.architecture); err != nil {
		return ManagedResult{}, err
	}
	if err = ctx.Err(); err != nil {
		return ManagedResult{}, err
	}
	if !resuming {
		if err = m.backupState(ctx, transaction); err != nil {
			return ManagedResult{}, err
		}
		if err = ctx.Err(); err != nil {
			return ManagedResult{}, err
		}
		if _, err = os.Lstat(m.path(managedBinary)); err == nil {
			transaction.PreviousSHA256, err = SHA256(m.path(managedBinary))
			if err != nil {
				return ManagedResult{}, err
			}
			if err = VerifyBinary(m.path(managedBinary), transaction.PreviousSHA256, m.architecture); err != nil {
				return ManagedResult{}, err
			}
			status, statusErr := m.status(ctx)
			if statusErr != nil {
				return ManagedResult{}, errors.New("cannot observe previous NetBird daemon before update")
			}
			transaction.PreviousVersion, err = daemonVersion(status)
			if err != nil {
				return ManagedResult{}, err
			}
			if err = installManagedBinary(m.path(managedBinary), m.previousBinary(transaction), transaction.PreviousSHA256, m.architecture); err != nil {
				return ManagedResult{}, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return ManagedResult{}, err
		}
		if err := m.retainRollbackExecutable(ctx, &transaction); err != nil {
			return ManagedResult{}, err
		}
		// Arm first: a crash after committing pending.json must never leave
		// a journal whose local recovery has no independent deadline timer.
		if err = m.armRollback(ctx, transaction); err != nil {
			return ManagedResult{}, err
		}
		if err := ctx.Err(); err != nil {
			return ManagedResult{}, err
		}
		if !time.Now().Before(transaction.RollbackDeadline) {
			return ManagedResult{}, errors.New("managed NetBird rollback deadline expired before journal commit")
		}
		if err = m.writeTransaction(transaction); err != nil {
			return ManagedResult{}, err
		}
		if err := m.pruneTransactions(transaction); err != nil {
			// The committed journal owns rollback now. Retry cleanup before
			// the next preparation; it cannot gate this node's recovery.
			slog.WarnContext(ctx, "NetBird rollback history cleanup deferred", "error", err)
		}
	} else {
		if err := m.retainRollbackExecutable(ctx, &transaction); err != nil {
			return transaction.ManagedResult, err
		}
		if err = m.armRollback(ctx, transaction); err != nil {
			return transaction.ManagedResult, err
		}
		if err = m.writeTransaction(transaction); err != nil {
			return transaction.ManagedResult, err
		}
	}
	unitBody, unit, err := readManagedStateFile(m.path("/etc/systemd/system/netbird.service"))
	if err != nil {
		return transaction.ManagedResult, err
	}
	status, statusErr := m.status(ctx)
	if err = ctx.Err(); err != nil {
		return transaction.ManagedResult, err
	}
	version, _ := daemonVersion(status)
	currentDigest, _ := SHA256(m.path(managedBinary))
	if !transaction.RestartRequired && (statusErr != nil || version != pin.Version || currentDigest != archive.BinarySHA256 || !unit.Exists || managedUnitSettings(string(unitBody)) != managedUnitSettings(managedService)) {
		// Persist before changing the unit or binary so a failed restart or
		// process crash cannot make an unchanged-version retry skip it.
		transaction.RestartRequired = true
		if err = m.writeTransaction(transaction); err != nil {
			return transaction.ManagedResult, err
		}
	}
	if err = m.configure(ctx, cfg); err != nil {
		return transaction.ManagedResult, err
	}
	if err = m.systemctl(ctx, "enable", "netbird.service"); err != nil {
		return transaction.ManagedResult, err
	}
	if err = ctx.Err(); err != nil {
		return transaction.ManagedResult, err
	}
	if transaction.RestartRequired {
		if err = installManagedBinary(binary, m.path(managedBinary), archive.BinarySHA256, m.architecture); err != nil {
			return transaction.ManagedResult, err
		}
		if err = m.systemctl(ctx, "daemon-reload"); err != nil {
			return transaction.ManagedResult, err
		}
		if err = m.systemctl(ctx, "restart", "netbird.service"); err != nil {
			return transaction.ManagedResult, err
		}
		transaction.RestartRequired = false
		if err = m.writeTransaction(transaction); err != nil {
			return transaction.ManagedResult, err
		}
	}
	if m.enroll(ctx, cfg) != nil {
		return transaction.ManagedResult, errors.New("managed NetBird enrollment or reconnect failed")
	}
	status, err = m.status(ctx)
	if err != nil {
		return transaction.ManagedResult, errors.New("cannot observe updated NetBird daemon")
	}
	version, err = daemonVersion(status)
	if err != nil || version != pin.Version {
		return transaction.ManagedResult, errors.New("running NetBird daemon does not match the pin")
	}
	return transaction.ManagedResult, nil
}

// ConfirmManaged accepts only the current transaction after the controller's
// peer, IP, DNS and application probes pass. It preserves the previous binary.
func ConfirmManaged(ctx context.Context, transactionID string) error {
	m, err := localManagedClient()
	if err != nil {
		return err
	}
	return m.finish(ctx, transactionID, false)
}

// RollbackManaged restores the persisted binary for an explicit controller
// action, including a confirmed transaction. It does not need OCI Vault.
func RollbackManaged(ctx context.Context, transactionID string) error {
	m, err := localManagedClient()
	if err != nil {
		return err
	}
	return m.finish(ctx, transactionID, true)
}

// RollbackPendingManaged is the local watchdog entry point. Confirmation
// cancels its authority; an explicit signed rollback may still restore the
// previous binary if the controller's later health checks fail.
func RollbackPendingManaged(ctx context.Context, transactionID string) error {
	m, err := localManagedClient()
	if err != nil {
		return err
	}
	return m.finishMode(ctx, transactionID, true, true)
}

func (m managedClient) finish(ctx context.Context, transactionID string, rollback bool) error {
	return m.finishMode(ctx, transactionID, rollback, false)
}

func (m managedClient) finishMode(ctx context.Context, transactionID string, rollback, pendingOnly bool) error {
	return m.finishModeWithProof(ctx, transactionID, rollback, pendingOnly, nil)
}

func (m managedClient) finishModeWithProof(ctx context.Context, transactionID string, rollback, pendingOnly bool, proof *ManagedRollbackProof) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !entityid.Valid(transactionID) || proof != nil && proof.PreviousTransactionID != "" && !entityid.Valid(proof.PreviousTransactionID) {
		return errors.New("invalid managed NetBird transaction identity")
	}
	lock, err := m.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	transaction, err := m.readTransaction()
	if err != nil {
		return err
	}
	if transaction.TransactionID != transactionID || transactionID == "" {
		// A watchdog armed before journal commit cannot replace completed state;
		// explicit worker rollback still requires its durable preparation proof.
		if rollback && entityid.Valid(transactionID) && !transaction.Pending &&
			(pendingOnly || proof != nil && !proof.InstallCommitted &&
				(!proof.InstallStarted || transaction.TransactionID == proof.PreviousTransactionID)) {
			// Preparation may arm an orphaned watchdog before journal commit.
			cleanup, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_ = m.systemctl(cleanup, "stop", rollbackUnit+".timer", rollbackUnit+".service")
			return nil
		}
		return errors.New("managed NetBird transaction identity does not match")
	}
	// An orphaned timer may run after this transaction's window was renewed.
	if rollback && pendingOnly && time.Now().Before(transaction.RollbackDeadline) {
		return nil
	}
	if !transaction.Pending {
		if !rollback && transaction.RolledBack {
			return errors.New("cannot confirm a rolled back NetBird transaction")
		}
		if !rollback || pendingOnly || transaction.RolledBack {
			return nil
		}
		// A post-confirmation rollback is itself recoverable if the worker
		// loses its controller or fails between replacement and restart.
		transaction.Pending = true
		transaction.RollbackDeadline = time.Now().Add(rollbackWindow)
		if err := m.retainRollbackExecutable(ctx, &transaction); err != nil {
			return err
		}
		if err := m.armRollback(ctx, transaction); err != nil {
			return err
		}
		if err := m.writeTransaction(transaction); err != nil {
			return err
		}
	}
	return m.finishTransaction(ctx, transaction, rollback)
}

// Caller holds managed.lock; recovery and explicit commands share this path.
func (m managedClient) finishTransaction(ctx context.Context, transaction managedTransaction, rollback bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if rollback {
		if transaction.PreviousSHA256 != "" {
			if err := VerifyBinary(m.previousBinary(transaction), transaction.PreviousSHA256, transaction.Architecture); err != nil {
				return err
			}
		}
		enabled, err := m.restoreState(ctx, transaction)
		if err != nil {
			return err
		}
		if transaction.PreviousSHA256 != "" {
			if err := installManagedBinary(m.previousBinary(transaction), m.path(managedBinary), transaction.PreviousSHA256, transaction.Architecture); err != nil {
				return err
			}
			if enabled {
				if err := m.systemctl(ctx, "enable", "netbird.service"); err != nil {
					return err
				}
			}
			if err := m.systemctl(ctx, "restart", "netbird.service"); err != nil {
				return err
			}
		} else {
			if err := removeManagedFile(m.path(managedBinary)); err != nil {
				return err
			}
		}
		transaction.Version, transaction.RolledBack = transaction.PreviousVersion, true
	} else if !time.Now().Before(transaction.RollbackDeadline) {
		return errors.New("managed NetBird confirmation arrived after rollback deadline")
	}
	transaction.Pending = false
	if err := m.writeTransaction(transaction); err != nil {
		return err
	}
	// The durable completed journal is the watchdog's guard. Failure to
	// stop its timer cannot undo confirmation or turn rollback into failure.
	_ = m.systemctl(ctx, "stop", rollbackUnit+".timer")
	return nil
}
