package vmguest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultInboxRoot = "/var/lib/terrascale/vmqual-inbox"
	DefaultDataRoot  = "/var/lib/terrascale/vmqual-data"
	DefaultSeedPath  = "/etc/terrascale/vmqual-guest-seed.json"
)

type Executor interface {
	Run(context.Context, string, []string, io.Writer, io.Writer) error
}

type ProcessExecutor struct{}

func (ProcessExecutor) Run(ctx context.Context, path string, args []string, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, path, args...)
	command.Env = []string{"HOME=/root", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Stdout = stdout
	command.Stderr = stderr
	command.WaitDelay = 2 * time.Second
	return command.Run()
}

type Config struct {
	InboxRoot      string
	DataRoot       string
	SeedPath       string
	Executor       Executor
	CommandTimeout time.Duration
	SessionTimeout time.Duration
}

func DefaultConfig() Config {
	return Config{InboxRoot: DefaultInboxRoot, DataRoot: DefaultDataRoot, SeedPath: DefaultSeedPath, Executor: ProcessExecutor{}, CommandTimeout: 30 * time.Second, SessionTimeout: 2 * time.Minute}
}

func (config Config) validate() (Config, error) {
	if config.InboxRoot == "" {
		config.InboxRoot = DefaultInboxRoot
	}
	if config.DataRoot == "" {
		config.DataRoot = DefaultDataRoot
	}
	if config.SeedPath == "" {
		config.SeedPath = DefaultSeedPath
	}
	if config.Executor == nil {
		config.Executor = ProcessExecutor{}
	}
	if config.CommandTimeout == 0 {
		config.CommandTimeout = 30 * time.Second
	}
	if config.SessionTimeout == 0 {
		config.SessionTimeout = 2 * time.Minute
	}
	for name, path := range map[string]string{"inbox": config.InboxRoot, "data": config.DataRoot, "seed": config.SeedPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
			return Config{}, fmt.Errorf("vmguest: %s path must be clean and absolute", name)
		}
	}
	if pathsOverlap(config.InboxRoot, config.DataRoot) || pathsOverlap(config.InboxRoot, config.SeedPath) || pathsOverlap(config.DataRoot, config.SeedPath) || config.CommandTimeout < time.Second || config.CommandTimeout > 2*time.Minute || config.SessionTimeout < time.Second || config.SessionTimeout > 5*time.Minute {
		return Config{}, errors.New("vmguest: control configuration is invalid")
	}
	return config, nil
}

// ServeForced handles one SSH forced-command request. A non-empty original
// command is rejected so sshd cannot turn this helper into an interactive or
// caller-selected command channel.
func ServeForced(ctx context.Context, input io.Reader, output io.Writer, originalCommand string, config Config) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if output == nil {
		return errors.New("vmguest: response writer is nil")
	}
	validated, err := config.validate()
	if err != nil {
		return err
	}
	sessionContext, cancel := context.WithTimeout(ctx, validated.SessionTimeout)
	defer cancel()
	response := Response{SchemaVersion: SchemaVersion}
	if originalCommand != "" {
		response.Error = "vmguest: SSH original command is not admitted"
		return encodeResponse(sessionContext, output, response)
	}
	request, err := decodeRequest(sessionContext, input)
	if err != nil {
		if sessionContext.Err() != nil {
			return sessionContext.Err()
		}
		response.Error = err.Error()
		return encodeResponse(sessionContext, output, response)
	}
	response, err = handleRequestContext(sessionContext, validated, request)
	if err != nil {
		return err
	}
	return encodeResponse(sessionContext, output, response)
}

func handleRequestContext(ctx context.Context, config Config, request Request) (Response, error) {
	done := make(chan Response, 1)
	go func() { done <- handleRequest(ctx, config, request) }()
	select {
	case response := <-done:
		return response, nil
	case <-ctx.Done():
		return Response{}, ctx.Err()
	}
}

func handleRequest(ctx context.Context, config Config, request Request) Response {
	response := Response{SchemaVersion: SchemaVersion}
	switch request.Operation {
	case OperationProbe:
		probe := collectProbe(ctx, config)
		response.Probe = &probe
	case OperationExecute:
		result := runCommand(ctx, config, request.Path, request.Args)
		response.Command = &result
	case OperationPut:
		if err := atomicWrite(config.InboxRoot, request.Path, request.Data, os.FileMode(request.Mode)); err != nil {
			response.Error = err.Error()
		}
	case OperationDataWrite:
		if err := atomicWrite(config.DataRoot, request.Path, request.Data, 0o600); err != nil {
			response.Error = err.Error()
		}
	case OperationDataRead:
		data, err := boundedRead(config.DataRoot, request.Path, MaxPersistentBytes)
		if err != nil {
			response.Error = err.Error()
		} else {
			response.Data = data
		}
	default:
		response.Error = "vmguest: operation is not admitted"
	}
	return response
}

func collectProbe(ctx context.Context, config Config) ProbeResult {
	return ProbeResult{
		Systemd:    runCommand(ctx, config, "/usr/bin/systemctl", []string{"is-system-running"}),
		PID1:       runCommand(ctx, config, "/usr/bin/readlink", []string{"/proc/1/exe"}),
		CgroupV2:   runCommand(ctx, config, "/usr/bin/stat", []string{"-fc", "%T", "/sys/fs/cgroup"}),
		DataMount:  runCommand(ctx, config, "/usr/bin/findmnt", []string{"-n", "-o", "SOURCE,FSTYPE,TARGET", "/var/lib/terrascale"}),
		Network:    runCommand(ctx, config, "/usr/bin/networkctl", []string{"status", "eth0", "--no-pager"}),
		Time:       runCommand(ctx, config, "/usr/bin/timedatectl", []string{"show", "--property=NTPSynchronized", "--value"}),
		SeedDigest: runCommand(ctx, config, "/usr/bin/sha256sum", []string{config.SeedPath}),
	}
}

func runCommand(ctx context.Context, config Config, path string, args []string) CommandResult {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := config.CommandTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stdout := &boundedWriter{limit: MaxOutputBytes}
	stderr := &boundedWriter{limit: MaxOutputBytes}
	result := CommandResult{ExitCode: 0}
	err := config.Executor.Run(commandContext, path, append([]string(nil), args...), stdout, stderr)
	result.Stdout, result.Stderr = stdout.Bytes(), stderr.Bytes()
	result.StdoutTruncated, result.StderrTruncated = stdout.truncated, stderr.truncated
	if err == nil {
		return result
	}
	result.ExitCode = -1
	if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
		result.ExitCode = 124
	} else {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			result.ExitCode = exitError.ExitCode()
		}
	}
	result.Error = err.Error()
	return result
}

func decodeRequest(ctx context.Context, reader io.Reader) (Request, error) {
	type result struct {
		request Request
		err     error
	}
	done := make(chan result, 1)
	go func() {
		request, err := DecodeRequest(reader)
		done <- result{request: request, err: err}
	}()
	select {
	case result := <-done:
		return result.request, result.err
	case <-ctx.Done():
		closeIO(reader)
		return Request{}, ctx.Err()
	}
}

func encodeResponse(ctx context.Context, writer io.Writer, response Response) error {
	done := make(chan error, 1)
	go func() { done <- json.NewEncoder(writer).Encode(response) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		closeIO(writer)
		return ctx.Err()
	}
}

func closeIO(value any) {
	if closer, ok := value.(io.Closer); ok {
		_ = closer.Close()
	}
}

func pathsOverlap(first, second string) bool {
	return pathInside(first, second) || pathInside(second, first)
}

func pathInside(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))))
}

type boundedWriter struct {
	data      []byte
	limit     int
	truncated bool
}

func (writer *boundedWriter) Write(data []byte) (int, error) {
	original := len(data)
	remaining := writer.limit - len(writer.data)
	if remaining > 0 {
		if len(data) > remaining {
			writer.data = append(writer.data, data[:remaining]...)
			writer.truncated = true
		} else {
			writer.data = append(writer.data, data...)
		}
	} else if len(data) > 0 {
		writer.truncated = true
	}
	return original, nil
}

func (writer *boundedWriter) Bytes() []byte { return append([]byte(nil), writer.data...) }
