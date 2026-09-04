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
	"time"
)

const (
	DefaultInboxRoot = "/run/terrascale/vmqual-inbox"
	DefaultDataRoot  = "/var/lib/terrascale/vmqual"
	DefaultSeedPath  = "/run/terrascale/guest-seed.json"
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
	return command.Run()
}

type Config struct {
	InboxRoot      string
	DataRoot       string
	SeedPath       string
	Executor       Executor
	CommandTimeout time.Duration
}

func DefaultConfig() Config {
	return Config{InboxRoot: DefaultInboxRoot, DataRoot: DefaultDataRoot, SeedPath: DefaultSeedPath, Executor: ProcessExecutor{}, CommandTimeout: 30 * time.Second}
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
	for name, path := range map[string]string{"inbox": config.InboxRoot, "data": config.DataRoot, "seed": config.SeedPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
			return Config{}, fmt.Errorf("vmguest: %s path must be clean and absolute", name)
		}
	}
	if config.InboxRoot == config.DataRoot || config.CommandTimeout < time.Second || config.CommandTimeout > 2*time.Minute {
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
	response := Response{SchemaVersion: SchemaVersion}
	if originalCommand != "" {
		response.Error = "vmguest: SSH original command is not admitted"
		return encodeResponse(output, response)
	}
	validated, err := config.validate()
	if err != nil {
		response.Error = err.Error()
		return encodeResponse(output, response)
	}
	request, err := DecodeRequest(input)
	if err != nil {
		response.Error = err.Error()
		return encodeResponse(output, response)
	}
	response = handleRequest(ctx, validated, request)
	return encodeResponse(output, response)
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
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
	} else if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
		result.ExitCode = 124
	}
	result.Error = err.Error()
	return result
}

func encodeResponse(writer io.Writer, response Response) error {
	return json.NewEncoder(writer).Encode(response)
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
