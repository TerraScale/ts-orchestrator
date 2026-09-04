package vmguest

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultInboxRoot  = "/var/lib/terrascale/vmqual-inbox"
	DefaultDataRoot   = "/var/lib/terrascale/vmqual-data"
	DefaultDataDevice = "/dev/vdb"
	DefaultSeedPath   = "/etc/terrascale/vmqual-guest-seed.json"
)

type Executor interface {
	Run(context.Context, string, []string, io.Writer, io.Writer) error
}

type NetworkDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
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
	InboxRoot               string
	DataRoot                string
	DataDevice              string
	SeedPath                string
	NetworkExchangeEndpoint string
	Executor                Executor
	NetworkDialer           NetworkDialer
	CommandTimeout          time.Duration
	SessionTimeout          time.Duration
}

func DefaultConfig() Config {
	return Config{InboxRoot: DefaultInboxRoot, DataRoot: DefaultDataRoot, DataDevice: DefaultDataDevice, SeedPath: DefaultSeedPath, Executor: ProcessExecutor{}, CommandTimeout: 30 * time.Second, SessionTimeout: 2 * time.Minute}
}

func (config Config) validate() (Config, error) {
	if config.InboxRoot == "" {
		config.InboxRoot = DefaultInboxRoot
	}
	if config.DataRoot == "" {
		config.DataRoot = DefaultDataRoot
	}
	if config.DataDevice == "" {
		config.DataDevice = DefaultDataDevice
	}
	if config.DataDevice != DefaultDataDevice {
		return Config{}, errors.New("vmguest: data device configuration is invalid")
	}
	if config.SeedPath == "" {
		config.SeedPath = DefaultSeedPath
	}
	if config.Executor == nil {
		config.Executor = ProcessExecutor{}
	}
	if config.NetworkDialer == nil {
		config.NetworkDialer = &net.Dialer{}
	}
	if config.NetworkExchangeEndpoint != "" && !validNetworkEndpoint(config.NetworkExchangeEndpoint) {
		return Config{}, errors.New("vmguest: network exchange endpoint configuration is invalid")
	}
	if config.CommandTimeout == 0 {
		config.CommandTimeout = 30 * time.Second
	}
	if config.SessionTimeout == 0 {
		config.SessionTimeout = 2 * time.Minute
	}
	paths := []struct {
		name string
		path string
	}{
		{name: "inbox", path: config.InboxRoot},
		{name: "data", path: config.DataRoot},
		{name: "seed", path: config.SeedPath},
	}
	resolved := make([]string, 0, len(paths))
	for _, candidate := range paths {
		name, path := candidate.name, candidate.path
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
			return Config{}, fmt.Errorf("vmguest: %s path must be clean and absolute", name)
		}
		physical, err := resolveExistingPath(path)
		if err != nil {
			return Config{}, fmt.Errorf("vmguest: resolve %s path: %w", name, err)
		}
		resolved = append(resolved, physical)
	}
	if pathsOverlap(resolved[0], resolved[1]) || pathsOverlap(resolved[0], resolved[2]) || pathsOverlap(resolved[1], resolved[2]) || config.CommandTimeout < time.Second || config.CommandTimeout > 2*time.Minute || config.SessionTimeout < time.Second || config.SessionTimeout > 5*time.Minute {
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
	stopReadCancellation, err := armReadCancellation(sessionContext, input)
	if err != nil {
		return err
	}
	defer stopReadCancellation()
	stopWriteCancellation, err := armWriteCancellation(sessionContext, output)
	if err != nil {
		return err
	}
	defer stopWriteCancellation()
	response := Response{SchemaVersion: SchemaVersion}
	if originalCommand != "" {
		response.Error = "vmguest: SSH original command is not admitted"
		return encodeResponse(sessionContext, output, response)
	}
	for _, root := range []string{validated.InboxRoot, validated.DataRoot} {
		if err := cleanupStorageRoot(sessionContext, root); err != nil {
			if sessionContext.Err() != nil {
				return sessionContext.Err()
			}
			response.Error = err.Error()
			return encodeResponse(sessionContext, output, response)
		}
	}
	request, err := decodeRequest(sessionContext, input)
	if err != nil {
		if sessionContext.Err() != nil {
			return sessionContext.Err()
		}
		response.Error = err.Error()
		return encodeResponse(sessionContext, output, response)
	}
	response = handleRequest(sessionContext, validated, request)
	if sessionContext.Err() != nil {
		return sessionContext.Err()
	}
	return encodeResponse(sessionContext, output, response)
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
		if err := atomicWriteWithinQuota(ctx, config.InboxRoot, request.Path, request.Data, os.FileMode(request.Mode), inboxStorageQuota); err != nil {
			response.Error = err.Error()
		}
	case OperationDataWrite:
		if err := atomicWriteWithinQuota(ctx, config.DataRoot, request.Path, request.Data, 0o600, persistentStorageQuota); err != nil {
			response.Error = err.Error()
		}
	case OperationDataRead:
		data, err := boundedRead(ctx, config.DataRoot, request.Path, MaxPersistentBytes)
		if err != nil {
			response.Error = err.Error()
		} else {
			response.Data = data
		}
	case OperationNetwork:
		data, err := networkExchange(ctx, config, request.Path, request.Data)
		if err != nil {
			response.Error = err.Error()
		} else {
			response.Data = data
		}
	case OperationStorage:
		observation, err := storageDiagnostic(ctx, config, request.Action)
		response.Storage = &observation
		if err != nil {
			response.Error = err.Error()
		}
	default:
		response.Error = "vmguest: operation is not admitted"
	}
	return response
}

func networkExchange(ctx context.Context, config Config, endpoint string, challenge []byte) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !validNetworkEndpoint(endpoint) || len(challenge) == 0 || len(challenge) > MaxNetworkBytes {
		return nil, errors.New("vmguest: network exchange parameters are invalid")
	}
	if config.NetworkExchangeEndpoint == "" || endpoint != config.NetworkExchangeEndpoint {
		return nil, errors.New("vmguest: network exchange endpoint is not authorized")
	}
	timeout := config.CommandTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	exchangeContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := config.NetworkDialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	connection, err := dialer.DialContext(exchangeContext, "tcp4", endpoint)
	if err != nil {
		if exchangeContext.Err() != nil {
			return nil, exchangeContext.Err()
		}
		return nil, errors.New("vmguest: connect network exchange")
	}
	stopClose := context.AfterFunc(exchangeContext, func() { _ = connection.Close() })
	defer func() {
		stopClose()
		_ = connection.Close()
	}()
	if deadline, present := exchangeContext.Deadline(); present {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, errors.New("vmguest: set network exchange deadline")
		}
	}

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(challenge)))
	if err := writeNetworkBytes(exchangeContext, connection, header[:]); err != nil {
		return nil, networkExchangeError(exchangeContext, "write challenge", err)
	}
	if err := writeNetworkBytes(exchangeContext, connection, challenge); err != nil {
		return nil, networkExchangeError(exchangeContext, "write challenge", err)
	}
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return nil, networkExchangeError(exchangeContext, "read response frame", err)
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > MaxNetworkBytes {
		return nil, errors.New("vmguest: network response size is invalid")
	}
	response := make([]byte, int(length))
	if _, err := io.ReadFull(connection, response); err != nil {
		return nil, networkExchangeError(exchangeContext, "read response", err)
	}
	var trailing [1]byte
	n, err := connection.Read(trailing[:])
	if n != 0 || err == nil {
		return nil, errors.New("vmguest: network response has trailing data")
	}
	if !errors.Is(err, io.EOF) {
		return nil, networkExchangeError(exchangeContext, "finish response", err)
	}
	if err := exchangeContext.Err(); err != nil {
		return nil, err
	}
	return response, nil
}

func writeNetworkBytes(ctx context.Context, writer io.Writer, data []byte) error {
	for len(data) != 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		written, err := writer.Write(data)
		if written < 0 || written > len(data) {
			return io.ErrShortWrite
		}
		if written > 0 {
			data = data[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return ctx.Err()
}

func networkExchangeError(ctx context.Context, action string, cause error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var networkError net.Error
	if errors.Is(cause, os.ErrDeadlineExceeded) || errors.As(cause, &networkError) && networkError.Timeout() {
		return context.DeadlineExceeded
	}
	return fmt.Errorf("vmguest: %s", action)
}

func collectProbe(ctx context.Context, config Config) ProbeResult {
	return ProbeResult{
		Systemd:    runCommand(ctx, config, "/usr/bin/systemctl", []string{"is-system-running"}),
		PID1:       runCommand(ctx, config, "/usr/bin/readlink", []string{"/proc/1/exe"}),
		CgroupV2:   runCommand(ctx, config, "/usr/bin/stat", []string{"-fc", "%T", "/sys/fs/cgroup"}),
		DataMount:  runCommand(ctx, config, "/usr/bin/findmnt", []string{"-no", "SOURCE,FSTYPE,TARGET", "/var/lib/terrascale"}),
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
	if reader == nil {
		return Request{}, errors.New("vmguest: request reader is nil")
	}
	return DecodeRequest(contextReader{ctx: ctx, reader: reader})
}

func encodeResponse(ctx context.Context, writer io.Writer, response Response) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return json.NewEncoder(contextWriter{ctx: ctx, writer: writer}).Encode(response)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := reader.reader.Read(data)
	if contextErr := reader.ctx.Err(); contextErr != nil {
		return n, contextErr
	}
	return n, err
}

type contextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (writer contextWriter) Write(data []byte) (int, error) {
	if err := writer.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := writer.writer.Write(data)
	if contextErr := writer.ctx.Err(); contextErr != nil {
		return n, contextErr
	}
	return n, err

}

type readDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

type writeDeadlineSetter interface {
	SetWriteDeadline(time.Time) error
}

func armReadCancellation(ctx context.Context, value any) (func(), error) {
	setter, ok := value.(readDeadlineSetter)
	if !ok {
		return func() {}, nil
	}
	if deadline, present := ctx.Deadline(); present {
		if err := setter.SetReadDeadline(deadline); err != nil {
			return nil, errors.New("vmguest: request reader does not support cancellation")
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = setter.SetReadDeadline(time.Now()) })
	return func() {
		if stop() {
			_ = setter.SetReadDeadline(time.Time{})
		}
	}, nil
}

func armWriteCancellation(ctx context.Context, value any) (func(), error) {
	setter, ok := value.(writeDeadlineSetter)
	if !ok {
		return func() {}, nil
	}
	if deadline, present := ctx.Deadline(); present {
		if err := setter.SetWriteDeadline(deadline); err != nil {
			return nil, errors.New("vmguest: response writer does not support cancellation")
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = setter.SetWriteDeadline(time.Now()) })
	return func() {
		if stop() {
			_ = setter.SetWriteDeadline(time.Time{})
		}
	}, nil
}

func resolveExistingPath(path string) (string, error) {
	current := path
	var missing []string
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Clean(resolved), nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", errors.New("vmguest: path has no existing ancestor")
		}
		missing = append(missing, filepath.Base(current))
		current = parent
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
