package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"golang.org/x/sys/unix"
)

const credentialChildTimeout = 15 * time.Second

var ErrLiveCredentials = errors.New("live controller credentials are invalid")

// LiveCredentials checks only manifest-pinned material at the fixed service
// directory. The root first-install process validates through the same binary
// under the dedicated service UID; restarts validate in the service process.
type LiveCredentials struct {
	Config                 natscell.Config
	ServiceUID             uint32
	ServiceGID             uint32
	ResponseKeyFile        string
	BrokerTicketKeyFile    string
	ValidateControllerKeys func() error
	directory              string
	allowUnsafeAncestors   bool
	runChild               func(context.Context, []byte, uint32, uint32) error
}

func NewLiveCredentialChecker(cfg natscell.Config, serviceUID, serviceGID uint32,
	responseKeyFile, brokerTicketKeyFile string, validateControllerKeys func() error,
) (LiveCredentials, error) {
	if serviceUID == 0 || serviceGID == 0 || cfg.Lab || cfg.Embedded == nil ||
		responseKeyFile == "" || brokerTicketKeyFile == "" || validateControllerKeys == nil {
		return LiveCredentials{}, ErrLiveCredentials
	}
	return LiveCredentials{Config: cfg, ServiceUID: serviceUID, ServiceGID: serviceGID,
		ResponseKeyFile: responseKeyFile, BrokerTicketKeyFile: brokerTicketKeyFile,
		ValidateControllerKeys: validateControllerKeys, directory: MaterialDirectory}, nil
}

func (check LiveCredentials) VerifyLiveCredentials(ctx context.Context, expected map[string]string) error {
	if check.ServiceUID == 0 || check.ServiceGID == 0 || check.Config.Lab || check.Config.Embedded == nil ||
		check.ValidateControllerKeys == nil ||
		len(expected) == 0 {
		return ErrLiveCredentials
	}
	if err := check.verifyPaths(expected); err != nil {
		return err
	}
	if err := check.verifyInventory(expected); err != nil {
		return err
	}
	if os.Geteuid() == int(check.ServiceUID) && os.Getegid() == int(check.ServiceGID) {
		if err := natscell.ValidateProductionCredentials(check.Config); err != nil {
			return err
		}
		return check.ValidateControllerKeys()
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("%w: credential verifier is neither root nor the service account", ErrLiveCredentials)
	}
	wire, err := protocol.EncodeJSON(CredentialChildRequest{
		Config: check.Config, UID: check.ServiceUID, GID: check.ServiceGID,
		ResponseKeyFile: check.ResponseKeyFile, BrokerTicketKeyFile: check.BrokerTicketKeyFile,
	})
	if err != nil {
		return fmt.Errorf("encode service credential preflight: %w", err)
	}
	run := check.runChild
	if run == nil {
		run = runCredentialChild
	}
	childCtx, cancel := context.WithTimeout(ctx, credentialChildTimeout)
	defer cancel()
	if err := run(childCtx, wire, check.ServiceUID, check.ServiceGID); err != nil {
		return fmt.Errorf("%w: service-account credential preflight: %v", ErrLiveCredentials, err)
	}
	return check.verifyInventory(expected)
}

func (check LiveCredentials) verifyPaths(expected map[string]string) error {
	e := check.Config.Embedded
	paths := []string{
		check.Config.CredentialsFile,
		check.Config.TLS.CAFile, check.Config.TLS.CertFile, check.Config.TLS.KeyFile,
		e.TLS.CAFile, e.TLS.CertFile, e.TLS.KeyFile,
		e.RouteTLS.CAFile, e.RouteTLS.CertFile, e.RouteTLS.KeyFile,
		e.OperatorJWTFile, e.SystemJWTFile, e.CellJWTFile, e.SystemCredentialsFile,
		e.TicketPublicKeyFile,
	}
	if e.RoutePasswordFile != "" {
		paths = append(paths, e.RoutePasswordFile)
	}
	paths = append(paths, check.ResponseKeyFile, check.BrokerTicketKeyFile)
	seen := make(map[string]bool, len(paths))
	for _, path := range paths {
		name := filepath.Base(path)
		if path == "" || path != filepath.Join(check.directory, name) || expected[name] == "" {
			return fmt.Errorf("%w: configured credential path is not pinned by signed material", ErrLiveCredentials)
		}
		seen[name] = true
	}
	for name := range expected {
		if !seen[name] {
			return fmt.Errorf("%w: signed credential material has no configured role", ErrLiveCredentials)
		}
	}
	return nil
}

func (check LiveCredentials) verifyInventory(expected map[string]string) error {
	dir, err := openMaterialDirectory(check.directory, check.ServiceUID, check.ServiceGID, 0o700, check.allowUnsafeAncestors)
	if err != nil {
		return fmt.Errorf("%w: open fixed credential directory: %v", ErrLiveCredentials, err)
	}
	defer unix.Close(dir)
	copyFD, err := unix.Dup(dir)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(copyFD), check.directory)
	entries, err := file.ReadDir(-1)
	_ = file.Close()
	if err != nil || len(entries) != len(expected) {
		return fmt.Errorf("%w: installed credential inventory differs", ErrLiveCredentials)
	}
	for _, entry := range entries {
		want := expected[entry.Name()]
		if want == "" {
			return fmt.Errorf("%w: unpinned credential file", ErrLiveCredentials)
		}
		content, err := readMaterial(dir, entry.Name(), check.ServiceUID, check.ServiceGID, want, bootstrap.MaxSecretBytes)
		if err != nil {
			return fmt.Errorf("%w: installed credential %s: %v", ErrLiveCredentials, entry.Name(), err)
		}
		clear(content)
	}
	return nil
}

// CredentialChildRequest is the bounded service-user preflight request passed
// over stdin to the same executable. It carries file paths, never secrets.
type CredentialChildRequest struct {
	Config              natscell.Config `json:"config"`
	UID                 uint32          `json:"uid"`
	GID                 uint32          `json:"gid"`
	ResponseKeyFile     string          `json:"responseKeyFile"`
	BrokerTicketKeyFile string          `json:"brokerTicketKeyFile"`
}

func runCredentialChild(ctx context.Context, wire []byte, uid, gid uint32) error {
	command := exec.CommandContext(ctx, "/proc/self/exe", "bootstrap-credential-check")
	command.Stdin = bytes.NewReader(wire)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.Env = []string{"PATH=/usr/bin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: uid, Gid: gid, Groups: []uint32{},
	}}
	if err := command.Run(); err != nil {
		return fmt.Errorf("service credential child exited unsuccessfully: %w", err)
	}
	return nil
}

// RunCredentialValidationChild is the hidden, read-only same-binary command.
// The parent supplies only configuration and expected service identity; no
// secret bytes or cloud authority are passed through stdin.
func RunCredentialValidationChild(input io.Reader, validateControllerKeys func(CredentialChildRequest) error) error {
	const maximum = 1 << 20
	wire, err := io.ReadAll(io.LimitReader(input, maximum+1))
	if err != nil || len(wire) == 0 || len(wire) > maximum {
		return ErrLiveCredentials
	}
	var request CredentialChildRequest
	if err := protocol.DecodeStrict(wire, &request, maximum); err != nil ||
		request.UID == 0 || request.GID == 0 ||
		request.ResponseKeyFile == "" || request.BrokerTicketKeyFile == "" || validateControllerKeys == nil ||
		os.Geteuid() != int(request.UID) || os.Getegid() != int(request.GID) {
		return ErrLiveCredentials
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return ErrLiveCredentials
	}
	if err := natscell.ValidateProductionCredentials(request.Config); err != nil {
		return err
	}
	return validateControllerKeys(request)
}

var _ LiveCredentialChecker = LiveCredentials{}
