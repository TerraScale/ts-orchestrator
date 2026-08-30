// Package bootstrap contains the process entry-point helpers used to start
// infrastructure owned by the orchestrator.
package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nats-io/nats-server/v2/server"
)

const (
	// NatsServerConfigPathLimit keeps a malformed command line from becoming
	// an unbounded filesystem operation. It also leaves room for normal Unix
	// socket and volume mount paths.
	NatsServerConfigPathLimit = 4096
	// NatsServerConfigSizeLimit bounds the input before handing it to the
	// NATS parser (which also follows NATS include directives).
	NatsServerConfigSizeLimit = 1 << 20
	// NatsServerReadinessLimit prevents an accidental or hostile timeout from
	// keeping a process alive indefinitely.
	NatsServerReadinessLimit   = 5 * time.Minute
	NatsServerDefaultReadiness = 30 * time.Second
)

// NatsServerConfig is the complete, explicit input to the dedicated NATS
// process mode. No defaults are taken from the environment or current
// working directory.
type NatsServerConfig struct {
	ConfigPath       string
	ReadinessTimeout time.Duration
}

// NatsServerRunner links the NATS server into the orchestrator binary. The
// caller must execute it as its own OS process; this runner intentionally has
// no controller lifecycle or shared state.
type NatsServerRunner struct {
	config NatsServerConfig
}

// NewNatsServerRunner validates the explicit process configuration. The file
// is parsed again by Run so a caller cannot accidentally run a path that was
// replaced between construction and execution.
func NewNatsServerRunner(config NatsServerConfig) (*NatsServerRunner, error) {
	if err := validateNatsServerConfig(config); err != nil {
		return nil, err
	}
	return &NatsServerRunner{config: config}, nil
}

// RunNatsServer starts a linked nats-server and blocks until cancellation or
// an unexpected server failure. A clean context cancellation returns
// context.Canceled after the server has fully shut down.
func RunNatsServer(ctx context.Context, config NatsServerConfig) error {
	if ctx == nil {
		return errors.New("nats server context is nil")
	}
	runner, err := NewNatsServerRunner(config)
	if err != nil {
		return err
	}
	return runner.Run(ctx)
}

// RunNATSServer is an acronym-compatible spelling of RunNatsServer.
func RunNATSServer(ctx context.Context, config NatsServerConfig) error {
	return RunNatsServer(ctx, config)
}

// RunEmbeddedNatsServer is a convenience for a future command dispatcher
// whose only mode-specific argument is the explicit configuration path.
func RunEmbeddedNatsServer(ctx context.Context, configPath string, readinessTimeout time.Duration) error {
	return RunNatsServer(ctx, NatsServerConfig{
		ConfigPath:       configPath,
		ReadinessTimeout: readinessTimeout,
	})
}

// Run starts the server after validating and parsing its configuration. The
// linked server remains in this goroutine's process, but this function is
// intended to be called from a dedicated OS process selected by the binary's
// command dispatcher.
func (r *NatsServerRunner) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nats server context is nil")
	}
	if err := validateNatsServerConfig(r.config); err != nil {
		return err
	}

	options, err := loadNatsServerOptions(r.config.ConfigPath)
	if err != nil {
		return err
	}
	if err := validateNatsServerOptions(options); err != nil {
		return err
	}

	serverInstance, err := server.NewServer(options)
	if err != nil {
		return errors.New("construct nats server: configuration was rejected")
	}
	fatalErrors := make(chan error, 1)
	// The stock logger calls os.Exit from Fatalf. A linked server must report
	// asynchronous listener failures to its owner instead of terminating the
	// controller process (or hiding the startup error).
	serverInstance.SetLogger(&natsServerLogger{fatalErrors: fatalErrors}, false, false)
	serverInstance.Start()

	if err := waitForNatsReadiness(ctx, serverInstance, r.config.ReadinessTimeout, fatalErrors); err != nil {
		shutdownNatsServer(serverInstance)
		return err
	}

	serverStopped := make(chan struct{})
	go func() {
		serverInstance.WaitForShutdown()
		close(serverStopped)
	}()

	select {
	case <-ctx.Done():
		shutdownNatsServer(serverInstance)
		<-serverStopped
		return ctx.Err()
	case err := <-fatalErrors:
		shutdownNatsServer(serverInstance)
		<-serverStopped
		return fmt.Errorf("nats server failed: %w", err)
	case <-serverStopped:
		return errors.New("nats server stopped unexpectedly")
	}
}

func loadNatsServerOptions(configPath string) (*server.Options, error) {
	configuration, err := readNatsServerConfig(configPath)
	if err != nil {
		return nil, err
	}
	if containsNatsIncludeDirective(configuration) {
		return nil, errors.New("nats server configuration must not use include directives")
	}

	// Parse an immutable private copy in the same directory. Relative TLS and
	// storage paths retain their documented base, while a replacement of the
	// deployment-supplied file cannot change the bytes after validation.
	temporary, err := os.CreateTemp(filepath.Dir(configPath), ".terrascale-nats-*.conf")
	if err != nil {
		return nil, errors.New("prepare nats server configuration for parsing")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if chmodErr := temporary.Chmod(0o600); chmodErr != nil {
		_ = temporary.Close()
		return nil, errors.New("prepare nats server configuration for parsing")
	}
	if _, writeErr := temporary.Write(configuration); writeErr != nil {
		_ = temporary.Close()
		return nil, errors.New("prepare nats server configuration for parsing")
	}
	if closeErr := temporary.Close(); closeErr != nil {
		return nil, errors.New("prepare nats server configuration for parsing")
	}

	options, err := server.ProcessConfigFile(temporaryPath)
	if err != nil {
		// Parser errors can contain authentication values and source snippets.
		return nil, errors.New("parse nats server configuration: configuration is invalid")
	}
	return options, nil
}

func validateNatsServerConfig(config NatsServerConfig) error {
	if config.ConfigPath == "" {
		return errors.New("nats server configuration path is required")
	}
	if len(config.ConfigPath) > NatsServerConfigPathLimit {
		return fmt.Errorf("nats server configuration path exceeds %d bytes", NatsServerConfigPathLimit)
	}
	if strings.IndexByte(config.ConfigPath, 0) >= 0 {
		return errors.New("nats server configuration path contains a NUL byte")
	}
	if !filepath.IsAbs(config.ConfigPath) {
		return errors.New("nats server configuration path must be absolute")
	}
	cleanPath := filepath.Clean(config.ConfigPath)
	if cleanPath != config.ConfigPath {
		return errors.New("nats server configuration path must be canonical")
	}
	if err := rejectSymlinkPath(cleanPath, false); err != nil {
		return fmt.Errorf("reject nats server configuration path: %w", err)
	}
	if _, err := readNatsServerConfig(cleanPath); err != nil {
		return err
	}
	if config.ReadinessTimeout < 0 || config.ReadinessTimeout > NatsServerReadinessLimit {
		return fmt.Errorf("nats server readiness timeout must be between zero and %s", NatsServerReadinessLimit)
	}
	return nil
}

func readNatsServerConfig(path string) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errors.New("nats server configuration file does not exist")
		}
		return nil, errors.New("stat nats server configuration file")
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, errors.New("nats server configuration must be a regular file, not a symbolic link")
	}
	if pathInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("nats server configuration is accessible by group or other users")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open nats server configuration file")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) || !openedInfo.Mode().IsRegular() {
		return nil, errors.New("nats server configuration changed while it was opened")
	}
	if openedInfo.Size() <= 0 {
		return nil, errors.New("nats server configuration file is empty")
	}
	if openedInfo.Size() > NatsServerConfigSizeLimit {
		return nil, fmt.Errorf("nats server configuration exceeds %d bytes", NatsServerConfigSizeLimit)
	}
	configuration, err := io.ReadAll(io.LimitReader(file, NatsServerConfigSizeLimit+1))
	if err != nil || len(configuration) > NatsServerConfigSizeLimit {
		return nil, errors.New("read bounded nats server configuration")
	}
	return configuration, nil
}

// containsNatsIncludeDirective rejects the NATS parser's recursive file-read
// feature. It ignores quoted values and the two comment forms accepted by the
// parser. Rejecting an extra bare key named include is an intentional
// fail-closed tradeoff for a single-file production configuration.
func containsNatsIncludeDirective(configuration []byte) bool {
	const include = "include"
	for line := range bytes.Lines(configuration) {
		quoted := byte(0)
		escaped := false
		for index := 0; index < len(line); index++ {
			character := line[index]
			if quoted != 0 {
				if quoted == '"' && character == '\\' && !escaped {
					escaped = true
					continue
				}
				if character == quoted && !escaped {
					quoted = 0
				}
				escaped = false
				continue
			}
			if character == '#' || character == '/' && index+1 < len(line) && line[index+1] == '/' {
				break
			}
			if character == '\'' || character == '"' {
				quoted = character
				continue
			}
			if index+len(include) <= len(line) && strings.EqualFold(string(line[index:index+len(include)]), include) {
				beforeBoundary := index == 0 || !isNatsIdentifierByte(line[index-1])
				after := index + len(include)
				afterBoundary := after == len(line) || !isNatsIdentifierByte(line[after])
				if beforeBoundary && afterBoundary {
					return true
				}
			}
		}
	}
	return false
}

func isNatsIdentifierByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || value == '_' || value == '-'
}

func validateNatsServerOptions(options *server.Options) error {
	if options == nil {
		return errors.New("nats server options are nil")
	}
	if !options.JetStream {
		return errors.New("nats server must enable JetStream")
	}
	if options.StoreDir == "" {
		return errors.New("nats server must use JetStream file storage")
	}
	if !filepath.IsAbs(options.StoreDir) {
		return errors.New("nats server JetStream store directory must be absolute")
	}
	if err := rejectSymlinkPath(filepath.Clean(options.StoreDir), true); err != nil {
		return fmt.Errorf("reject JetStream store directory: %w", err)
	}
	if info, err := os.Stat(options.StoreDir); err == nil {
		if !info.IsDir() {
			return errors.New("nats server JetStream store path is not a directory")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return errors.New("nats server JetStream store directory is accessible by group or other users")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat JetStream store directory: %w", err)
	}

	if options.TLSConfig == nil || len(options.TLSConfig.Certificates) == 0 {
		return errors.New("nats server must configure TLS with a server certificate")
	}
	if options.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert || options.TLSConfig.ClientCAs == nil {
		return errors.New("nats server must require and verify client certificates")
	}
	if options.TLSConfig.InsecureSkipVerify || options.AllowNonTLS {
		return errors.New("nats server TLS must not allow insecure connections")
	}
	if options.TLSConfig.MinVersion < tls.VersionTLS13 {
		return errors.New("nats server TLS minimum version must be 1.3")
	}

	configuredAccounts := 0
	for _, account := range options.Accounts {
		if account != nil && account.Name != "" && account.Name != "$G" {
			configuredAccounts++
		}
	}
	if configuredAccounts == 0 {
		return errors.New("nats server must configure at least one non-global account")
	}
	if options.NoAuthUser != "" {
		return errors.New("nats server must not configure a no-auth user")
	}
	if len(options.Users) == 0 && len(options.Nkeys) == 0 && options.Username == "" && options.Password == "" && options.Authorization == "" && options.AuthCallout == nil {
		return errors.New("nats server must configure non-empty authorization")
	}
	return nil
}

// rejectSymlinkPath checks each existing component, including the final
// component. For an as-yet uncreated store directory, the final component is
// allowed to be absent while all existing parents remain checked.
func rejectSymlinkPath(path string, allowMissingFinal bool) error {
	volume := filepath.VolumeName(path)
	remainder := strings.TrimPrefix(path, volume)
	if remainder == "" {
		return nil
	}
	current := volume + string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(remainder, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			if allowMissingFinal && errors.Is(err, fs.ErrNotExist) && current == path {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("path contains a symbolic link")
		}
	}
	return nil
}

func waitForNatsReadiness(ctx context.Context, instance *server.Server, timeout time.Duration, fatalErrors <-chan error) error {
	if timeout == 0 {
		timeout = NatsServerDefaultReadiness
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if instance.ReadyForConnections(1 * time.Millisecond) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-fatalErrors:
			return fmt.Errorf("nats server failed during startup: %w", err)
		case <-deadline.C:
			return fmt.Errorf("nats server did not become ready within %s", timeout)
		case <-ticker.C:
		}
	}
}

func shutdownNatsServer(instance *server.Server) {
	instance.Shutdown()
	instance.WaitForShutdown()
}

type natsServerLogger struct {
	fatalErrors chan<- error
}

func (l *natsServerLogger) Noticef(string, ...any) {}
func (l *natsServerLogger) Warnf(string, ...any)   {}
func (l *natsServerLogger) Errorf(string, ...any)  {}
func (l *natsServerLogger) Debugf(string, ...any)  {}
func (l *natsServerLogger) Tracef(string, ...any)  {}
func (l *natsServerLogger) Fatalf(format string, args ...any) {
	// NATS log messages may interpolate credentials or configuration text.
	// The bootstrap boundary exposes only a stable, non-secret failure.
	err := errors.New("nats server reported a fatal error")
	select {
	case l.fatalErrors <- err:
	default:
	}
}
