// Package vmguest implements the I-12 test-only control protocol used inside
// disposable Firecracker guests. It is not a production host-agent API.
package vmguest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	SchemaVersion      = 1
	MaxRequestBytes    = 48 << 20
	MaxTransferBytes   = 32 << 20
	MaxPersistentBytes = 1 << 20
	MaxOutputBytes     = 256 << 10
)

type Operation string

const (
	OperationProbe     Operation = "probe"
	OperationExecute   Operation = "execute"
	OperationPut       Operation = "put"
	OperationDataWrite Operation = "data-write"
	OperationDataRead  Operation = "data-read"
)

// Request is one bounded operation. Data is base64 encoded by encoding/json.
type Request struct {
	SchemaVersion int       `json:"schemaVersion"`
	Operation     Operation `json:"operation"`
	Path          string    `json:"path,omitempty"`
	Args          []string  `json:"args,omitempty"`
	Data          []byte    `json:"data,omitempty"`
	Mode          uint32    `json:"mode,omitempty"`
}

// CommandResult records a direct argv execution without confusing a non-zero
// command status with a transport or protocol failure.
type CommandResult struct {
	ExitCode        int    `json:"exitCode"`
	Stdout          []byte `json:"stdout,omitempty"`
	Stderr          []byte `json:"stderr,omitempty"`
	StdoutTruncated bool   `json:"stdoutTruncated,omitempty"`
	StderrTruncated bool   `json:"stderrTruncated,omitempty"`
	Error           string `json:"error,omitempty"`
}

// ProbeResult contains raw guest facts. The controller compares them with its
// own VM identity, seed digest, topology, and release manifest.
type ProbeResult struct {
	Systemd    CommandResult `json:"systemd"`
	PID1       CommandResult `json:"pid1"`
	CgroupV2   CommandResult `json:"cgroupV2"`
	DataMount  CommandResult `json:"dataMount"`
	Network    CommandResult `json:"network"`
	Time       CommandResult `json:"time"`
	SeedDigest CommandResult `json:"seedDigest"`
}

// Response is always emitted for a decoded SSH request. Error denotes a
// protocol or control-operation failure, not a diagnostic command exit.
type Response struct {
	SchemaVersion int            `json:"schemaVersion"`
	Command       *CommandResult `json:"command,omitempty"`
	Probe         *ProbeResult   `json:"probe,omitempty"`
	Data          []byte         `json:"data,omitempty"`
	Error         string         `json:"error,omitempty"`
}

var relativePartPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,79})$`)

func DecodeRequest(reader io.Reader) (Request, error) {
	if reader == nil {
		return Request{}, errors.New("vmguest: request reader is nil")
	}
	limited := &io.LimitedReader{R: reader, N: int64(MaxRequestBytes) + 1}
	decoder := json.NewDecoder(limited)
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		if limited.N == 0 {
			return Request{}, errors.New("vmguest: request size is invalid")
		}
		return Request{}, errors.New("vmguest: request JSON is invalid")
	}
	var request Request
	seen := make(map[string]bool, 6)
	for decoder.More() {
		token, err := decoder.Token()
		field, ok := token.(string)
		if err != nil || !ok || seen[field] {
			return Request{}, errors.New("vmguest: request fields are invalid")
		}
		seen[field] = true
		switch field {
		case "schemaVersion":
			err = decodeNonNull(decoder, &request.SchemaVersion)
		case "operation":
			err = decodeNonNull(decoder, &request.Operation)
		case "path":
			err = decodeNonNull(decoder, &request.Path)
		case "args":
			err = decodeNonNull(decoder, &request.Args)
		case "data":
			err = decodeNonNull(decoder, &request.Data)
		case "mode":
			err = decodeNonNull(decoder, &request.Mode)
		default:
			return Request{}, errors.New("vmguest: request contains an unknown field")
		}
		if err != nil {
			if limited.N == 0 {
				return Request{}, errors.New("vmguest: request size is invalid")
			}
			return Request{}, errors.New("vmguest: request JSON is invalid")
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return Request{}, errors.New("vmguest: request JSON is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Request{}, errors.New("vmguest: request has trailing data")
	}
	if limited.N == 0 {
		return Request{}, errors.New("vmguest: request size is invalid")
	}
	if err := request.Validate(); err != nil {
		return Request{}, err
	}
	return request, nil
}

type nonNull[T any] struct {
	value T
}

func (value *nonNull[T]) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return errors.New("null is not admitted")
	}
	return json.Unmarshal(data, &value.value)
}

func decodeNonNull[T any](decoder *json.Decoder, target *T) error {
	var value nonNull[T]
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	*target = value.value
	return nil
}

func (request Request) Validate() error {
	if request.SchemaVersion != SchemaVersion {
		return fmt.Errorf("vmguest: unsupported request schema %d", request.SchemaVersion)
	}
	for _, arg := range request.Args {
		if strings.IndexByte(arg, 0) >= 0 || len(arg) > 4096 {
			return errors.New("vmguest: command argument is invalid")
		}
	}
	switch request.Operation {
	case OperationProbe:
		if request.Path != "" || len(request.Args) != 0 || len(request.Data) != 0 || request.Mode != 0 {
			return errors.New("vmguest: probe request contains unrelated fields")
		}
	case OperationExecute:
		if len(request.Data) != 0 || request.Mode != 0 || !admittedDiagnostic(request.Path, request.Args) {
			return errors.New("vmguest: diagnostic command is not admitted")
		}
	case OperationPut:
		if !validRelativePath(request.Path) || len(request.Args) != 0 || len(request.Data) == 0 || len(request.Data) > MaxTransferBytes || (request.Mode != 0o600 && request.Mode != 0o644) {
			return errors.New("vmguest: artifact transfer is invalid")
		}
	case OperationDataWrite:
		if !validRelativePath(request.Path) || len(request.Args) != 0 || len(request.Data) == 0 || len(request.Data) > MaxPersistentBytes || request.Mode != 0 {
			return errors.New("vmguest: persistent write is invalid")
		}
	case OperationDataRead:
		if !validRelativePath(request.Path) || len(request.Args) != 0 || len(request.Data) != 0 || request.Mode != 0 {
			return errors.New("vmguest: persistent read is invalid")
		}
	default:
		return errors.New("vmguest: operation is not admitted")
	}
	return nil
}

func validRelativePath(value string) bool {
	if value == "" || len(value) > 240 || filepath.IsAbs(value) || filepath.Clean(value) != value || value == "." {
		return false
	}
	parts := strings.Split(value, string(filepath.Separator))
	if len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if part == "." || part == ".." || !relativePartPattern.MatchString(part) {
			return false
		}
	}
	return true
}

func admittedDiagnostic(path string, args []string) bool {
	key := strings.Join(args, "\x00")
	switch path {
	case "/usr/bin/systemctl":
		if key == "is-system-running" || key == "is-system-running\x00--wait" {
			return true
		}
		if len(args) == 2 && args[0] == "is-active" && admittedUnit(args[1]) {
			return true
		}
		return len(args) == 3 && args[0] == "show" && admittedUnit(args[1]) && args[2] == "--property=MainPID,ActiveState,SubState"
	case "/usr/bin/readlink":
		return key == "/proc/1/exe"
	case "/usr/bin/stat":
		return key == "-fc\x00%T\x00/sys/fs/cgroup"
	case "/usr/bin/findmnt":
		return key == "-n\x00-o\x00SOURCE,FSTYPE,TARGET\x00/var/lib/terrascale"
	case "/usr/bin/networkctl":
		return key == "status\x00eth0\x00--no-pager"
	case "/usr/bin/timedatectl":
		return key == "show\x00--property=NTPSynchronized\x00--value"
	case "/usr/bin/sha256sum":
		return len(args) == 1 && admittedDigestPath(args[0])
	default:
		return false
	}
}

func admittedUnit(value string) bool {
	return value == "ts-node.service" || value == "terrascale-orchestrator.service" || value == "terrabase.service"
}

func admittedDigestPath(value string) bool {
	if value == DefaultSeedPath || value == "/usr/local/libexec/terrascale-vmqual-control" {
		return true
	}
	const root = "/opt/terrascale/"
	if !strings.HasPrefix(value, root) || filepath.Clean(value) != value {
		return false
	}
	relative := strings.TrimPrefix(value, root)
	return validRelativePath(relative)
}
