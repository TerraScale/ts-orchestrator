// Package vmguest implements the I-12 test-only control protocol used inside
// disposable Firecracker guests. It is not a production host-agent API.
package vmguest

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	SchemaVersion      = 1
	MaxRequestBytes    = 24 << 20
	MaxTransferBytes   = 16 << 20
	MaxPersistentBytes = 1 << 20
	MaxNetworkBytes    = 4 << 10
	MaxOutputBytes     = 256 << 10

	maxFieldNameBytes = 16
	maxOperationBytes = 18
	maxActionBytes    = 16
	maxPathBytes      = 240
	maxArgumentBytes  = 4096
	maxRequestArgs    = 7
	maxIntegerBytes   = 20
)

const (
	requestFieldSchemaVersion uint8 = 1 << iota
	requestFieldOperation
	requestFieldPath
	requestFieldArgs
	requestFieldData
	requestFieldMode
	requestFieldAction
)

type Operation string

const (
	OperationProbe     Operation = "probe"
	OperationExecute   Operation = "execute"
	OperationPut       Operation = "put"
	OperationDataWrite Operation = "data-write"
	OperationDataRead  Operation = "data-read"
	OperationNetwork   Operation = "network-exchange"
	OperationStorage   Operation = "storage-diagnostic"
)

type StorageAction string

const (
	StorageActionObserve    StorageAction = "observe"
	StorageActionProbeWrite StorageAction = "probe-write"
	StorageActionFillENOSPC StorageAction = "fill-enospc"
	StorageActionClearFill  StorageAction = "clear-fill"
	StorageActionFSCKRepair StorageAction = "fsck-repair"
	StorageActionFSCKCheck  StorageAction = "fsck-check"
	StorageActionGrow       StorageAction = "grow"
)

type StorageErrno string

const (
	StorageErrnoNone   StorageErrno = ""
	StorageErrnoENOSPC StorageErrno = "ENOSPC"
	StorageErrnoEIO    StorageErrno = "EIO"
	StorageErrnoEROFS  StorageErrno = "EROFS"
	StorageErrnoENODEV StorageErrno = "ENODEV"
)

// Request is one bounded operation. Data is base64 encoded by encoding/json.
type Request struct {
	SchemaVersion int           `json:"schemaVersion"`
	Operation     Operation     `json:"operation"`
	Path          string        `json:"path,omitempty"`
	Args          []string      `json:"args,omitempty"`
	Data          []byte        `json:"data,omitempty"`
	Mode          uint32        `json:"mode,omitempty"`
	Action        StorageAction `json:"action,omitempty"`

	decodedFields uint8
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

// StorageObservation contains only evidence gathered from the configured
// persistent data root and the device bound into the trusted guest seed.
type StorageObservation struct {
	Action             StorageAction `json:"action"`
	Device             string        `json:"device"`
	MountPath          string        `json:"mountPath"`
	Filesystem         string        `json:"filesystem"`
	Mounted            bool          `json:"mounted"`
	ReadOnly           bool          `json:"readOnly"`
	TotalBytes         uint64        `json:"totalBytes"`
	AvailableBytes     uint64        `json:"availableBytes"`
	AttemptedBytes     uint64        `json:"attemptedBytes"`
	WrittenBytes       uint64        `json:"writtenBytes"`
	Errno              StorageErrno  `json:"errno"`
	ExitCode           int           `json:"exitCode"`
	CorruptionDetected bool          `json:"corruptionDetected"`
	Repaired           bool          `json:"repaired"`
	Healthy            bool          `json:"healthy"`
}

// Response is always emitted for a decoded SSH request. Error denotes a
// protocol or control-operation failure, not a diagnostic command exit.
type Response struct {
	SchemaVersion int                 `json:"schemaVersion"`
	Command       *CommandResult      `json:"command,omitempty"`
	Probe         *ProbeResult        `json:"probe,omitempty"`
	Storage       *StorageObservation `json:"storage,omitempty"`
	Data          []byte              `json:"data,omitempty"`
	Error         string              `json:"error,omitempty"`
}

var (
	relativePartPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,79})$`)
	strictBase64        = base64.StdEncoding.Strict()
)

var (
	errRequestJSONInvalid = errors.New("vmguest: request JSON is invalid")
	errRequestSizeInvalid = errors.New("vmguest: request size is invalid")
	errRequestFields      = errors.New("vmguest: request fields are invalid")
	errRequestUnknown     = errors.New("vmguest: request contains an unknown field")
	errRequestTrailing    = errors.New("vmguest: request has trailing data")
	errRequestNull        = errors.New("vmguest: request fields must not be null")
)

func DecodeRequest(reader io.Reader) (Request, error) {
	if reader == nil {
		return Request{}, errors.New("vmguest: request reader is nil")
	}
	parser := requestJSONParser{reader: bufio.NewReaderSize(io.LimitReader(reader, MaxRequestBytes+1), 4<<10)}
	request, err := parser.parse()
	if err != nil {
		return Request{}, err
	}
	if err := request.Validate(); err != nil {
		return Request{}, err
	}
	return request, nil
}

type requestJSONParser struct {
	reader    *bufio.Reader
	bytesRead int
	pending   byte
	hasByte   bool
}

func (parser *requestJSONParser) parse() (Request, error) {
	first, err := parser.nextNonSpace()
	if err != nil {
		return Request{}, parser.publicError(err)
	}
	if first != '{' {
		return Request{}, errRequestJSONInvalid
	}

	var request Request
	var seen uint8
	next, err := parser.nextNonSpace()
	if err != nil {
		return Request{}, parser.publicError(err)
	}
	if next != '}' {
		parser.unreadByte(next)
		for {
			fieldStart, fieldErr := parser.nextNonSpace()
			if fieldErr != nil {
				return Request{}, parser.publicError(fieldErr)
			}
			if fieldStart != '"' {
				return Request{}, errRequestJSONInvalid
			}
			field, fieldErr := parser.readString(maxFieldNameBytes)
			if fieldErr != nil {
				return Request{}, parser.publicError(fieldErr)
			}
			fieldBit, known := requestFieldBit(field)
			if !known {
				return Request{}, errRequestUnknown
			}
			if seen&fieldBit != 0 {
				return Request{}, errRequestFields
			}
			seen |= fieldBit

			colon, colonErr := parser.nextNonSpace()
			if colonErr != nil {
				return Request{}, parser.publicError(colonErr)
			}
			if colon != ':' {
				return Request{}, errRequestJSONInvalid
			}
			if fieldErr = parser.decodeField(field, &request); fieldErr != nil {
				return Request{}, parser.publicError(fieldErr)
			}

			delimiter, delimiterErr := parser.nextNonSpace()
			if delimiterErr != nil {
				return Request{}, parser.publicError(delimiterErr)
			}
			switch delimiter {
			case '}':
				goto complete
			case ',':
				continue
			default:
				return Request{}, errRequestJSONInvalid
			}
		}
	}

complete:
	request.decodedFields = seen
	trailing, err := parser.nextNonSpace()
	if err == nil {
		_ = trailing
		return Request{}, errRequestTrailing
	}
	if !errors.Is(err, io.EOF) {
		return Request{}, parser.publicError(err)
	}
	return request, nil
}

func requestFieldBit(field string) (uint8, bool) {
	switch field {
	case "schemaVersion":
		return requestFieldSchemaVersion, true
	case "operation":
		return requestFieldOperation, true
	case "path":
		return requestFieldPath, true
	case "args":
		return requestFieldArgs, true
	case "data":
		return requestFieldData, true
	case "mode":
		return requestFieldMode, true
	case "action":
		return requestFieldAction, true
	default:
		return 0, false
	}
}

func (parser *requestJSONParser) decodeField(field string, request *Request) error {
	switch field {
	case "schemaVersion":
		return parser.decodeInteger(&request.SchemaVersion)
	case "operation":
		value, err := parser.decodeString(maxOperationBytes)
		request.Operation = Operation(value)
		return err
	case "path":
		value, err := parser.decodeString(maxPathBytes)
		request.Path = value
		return err
	case "args":
		value, err := parser.decodeStringList()
		request.Args = value
		return err
	case "data":
		value, err := parser.decodeBase64()
		request.Data = value
		return err
	case "mode":
		return parser.decodeInteger(&request.Mode)
	case "action":
		value, err := parser.decodeString(maxActionBytes)
		request.Action = StorageAction(value)
		return err
	default:
		return errRequestUnknown
	}
}

func (parser *requestJSONParser) decodeString(limit int) (string, error) {
	start, err := parser.nextNonSpace()
	if err != nil {
		return "", err
	}
	if start == 'n' {
		return "", parser.rejectNull()
	}
	if start != '"' {
		return "", errRequestJSONInvalid
	}
	return parser.readString(limit)
}

func (parser *requestJSONParser) readString(limit int) (string, error) {
	value := make([]byte, 0, min(limit, 256))
	err := parser.readStringBytes(limit, func(part []byte) error {
		value = append(value, part...)
		return nil
	})
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func (parser *requestJSONParser) decodeStringList() ([]string, error) {
	start, err := parser.nextNonSpace()
	if err != nil {
		return nil, err
	}
	if start == 'n' {
		return nil, parser.rejectNull()
	}
	if start != '[' {
		return nil, errRequestJSONInvalid
	}
	next, err := parser.nextNonSpace()
	if err != nil {
		return nil, err
	}
	if next == ']' {
		return []string{}, nil
	}
	parser.unreadByte(next)

	values := make([]string, 0, maxRequestArgs)
	for {
		if len(values) == maxRequestArgs {
			return nil, errRequestFields
		}
		value, valueErr := parser.decodeString(maxArgumentBytes)
		if valueErr != nil {
			return nil, valueErr
		}
		values = append(values, value)
		delimiter, delimiterErr := parser.nextNonSpace()
		if delimiterErr != nil {
			return nil, delimiterErr
		}
		switch delimiter {
		case ']':
			return values, nil
		case ',':
			continue
		default:
			return nil, errRequestJSONInvalid
		}
	}
}

func (parser *requestJSONParser) decodeBase64() ([]byte, error) {
	start, err := parser.nextNonSpace()
	if err != nil {
		return nil, err
	}
	if start == 'n' {
		return nil, parser.rejectNull()
	}
	if start != '"' {
		return nil, errRequestJSONInvalid
	}
	decoder := boundedBase64Decoder{maximum: MaxTransferBytes}
	if err := parser.readStringBytes(base64.StdEncoding.EncodedLen(MaxTransferBytes), decoder.write); err != nil {
		return nil, err
	}
	return decoder.finish()
}

func (parser *requestJSONParser) decodeInteger(target any) error {
	start, err := parser.nextNonSpace()
	if err != nil {
		return err
	}
	if start == 'n' {
		return parser.rejectNull()
	}
	if start < '0' || start > '9' {
		return errRequestJSONInvalid
	}
	encoded := []byte{start}
	for {
		next, readErr := parser.readByte()
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return readErr
		}
		if isJSONSpace(next) || next == ',' || next == '}' || next == ']' {
			parser.unreadByte(next)
			break
		}
		if next < '0' || next > '9' || encoded[0] == '0' {
			return errRequestJSONInvalid
		}
		if len(encoded) == maxIntegerBytes {
			return errRequestFields
		}
		encoded = append(encoded, next)
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		return errRequestJSONInvalid
	}
	return nil
}

func (parser *requestJSONParser) rejectNull() error {
	for _, expected := range []byte("ull") {
		actual, err := parser.readByte()
		if err != nil {
			return parser.stringReadError(err)
		}
		if actual != expected {
			return errRequestJSONInvalid
		}
	}
	return errRequestNull
}

func (parser *requestJSONParser) readStringBytes(limit int, emit func([]byte) error) error {
	decoded := 0
	var plain [4 << 10]byte
	plainLength := 0
	emitBounded := func(part []byte) error {
		if len(part) > limit-decoded {
			return errRequestFields
		}
		decoded += len(part)
		return emit(part)
	}
	flushPlain := func() error {
		if plainLength == 0 {
			return nil
		}
		err := emitBounded(plain[:plainLength])
		plainLength = 0
		return err
	}
	appendPlain := func(part []byte) error {
		if len(part) > limit-decoded-plainLength {
			return errRequestFields
		}
		for len(part) != 0 {
			count := copy(plain[plainLength:], part)
			plainLength += count
			part = part[count:]
			if plainLength == len(plain) {
				if err := flushPlain(); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for {
		current, err := parser.readByte()
		if err != nil {
			return parser.stringReadError(err)
		}
		switch {
		case current == '"':
			return flushPlain()
		case current == '\\':
			part, width, escapeErr := parser.readEscape()
			if escapeErr != nil {
				return escapeErr
			}
			if err := appendPlain(part[:width]); err != nil {
				return err
			}
		case current < 0x20:
			return errRequestJSONInvalid
		case current < utf8.RuneSelf:
			if decoded+plainLength == limit {
				return errRequestFields
			}
			plain[plainLength] = current
			plainLength++
			if plainLength == len(plain) {
				if err := flushPlain(); err != nil {
					return err
				}
			}
		default:
			part, width, utf8Err := parser.readUTF8(current)
			if utf8Err != nil {
				return utf8Err
			}
			if err := appendPlain(part[:width]); err != nil {
				return err
			}
		}
	}
}

func (parser *requestJSONParser) readEscape() ([utf8.UTFMax]byte, int, error) {
	var encoded [utf8.UTFMax]byte
	escaped, err := parser.readByte()
	if err != nil {
		return encoded, 0, parser.stringReadError(err)
	}
	switch escaped {
	case '"', '\\', '/':
		encoded[0] = escaped
	case 'b':
		encoded[0] = '\b'
	case 'f':
		encoded[0] = '\f'
	case 'n':
		encoded[0] = '\n'
	case 'r':
		encoded[0] = '\r'
	case 't':
		encoded[0] = '\t'
	case 'u':
		value, unicodeErr := parser.readUnicodeEscape()
		if unicodeErr != nil {
			return encoded, 0, unicodeErr
		}
		width := utf8.EncodeRune(encoded[:], value)
		return encoded, width, nil
	default:
		return encoded, 0, errRequestJSONInvalid
	}
	return encoded, 1, nil
}

func (parser *requestJSONParser) readUnicodeEscape() (rune, error) {
	first, err := parser.readHex16()
	if err != nil {
		return 0, err
	}
	if first >= 0xdc00 && first <= 0xdfff {
		return 0, errRequestJSONInvalid
	}
	if first < 0xd800 || first > 0xdbff {
		return rune(first), nil
	}
	slash, err := parser.readByte()
	if err != nil {
		return 0, parser.stringReadError(err)
	}
	if slash != '\\' {
		return 0, errRequestJSONInvalid
	}
	marker, err := parser.readByte()
	if err != nil {
		return 0, parser.stringReadError(err)
	}
	if marker != 'u' {
		return 0, errRequestJSONInvalid
	}
	second, err := parser.readHex16()
	if err != nil {
		return 0, err
	}
	if second < 0xdc00 || second > 0xdfff {
		return 0, errRequestJSONInvalid
	}
	return utf16.DecodeRune(rune(first), rune(second)), nil
}

func (parser *requestJSONParser) readHex16() (uint16, error) {
	var result uint16
	for range 4 {
		current, err := parser.readByte()
		if err != nil {
			return 0, parser.stringReadError(err)
		}
		result <<= 4
		switch {
		case current >= '0' && current <= '9':
			result |= uint16(current - '0')
		case current >= 'a' && current <= 'f':
			result |= uint16(current-'a') + 10
		case current >= 'A' && current <= 'F':
			result |= uint16(current-'A') + 10
		default:
			return 0, errRequestJSONInvalid
		}
	}
	return result, nil
}

func (parser *requestJSONParser) readUTF8(first byte) ([utf8.UTFMax]byte, int, error) {
	var encoded [utf8.UTFMax]byte
	width := 0
	switch {
	case first >= 0xc2 && first <= 0xdf:
		width = 2
	case first >= 0xe0 && first <= 0xef:
		width = 3
	case first >= 0xf0 && first <= 0xf4:
		width = 4
	default:
		return encoded, 0, errRequestJSONInvalid
	}
	encoded[0] = first
	for index := 1; index < width; index++ {
		current, err := parser.readByte()
		if err != nil {
			return encoded, 0, parser.stringReadError(err)
		}
		encoded[index] = current
	}
	_, actualWidth := utf8.DecodeRune(encoded[:width])
	if actualWidth != width {
		return encoded, 0, errRequestJSONInvalid
	}
	return encoded, width, nil
}

func (parser *requestJSONParser) nextNonSpace() (byte, error) {
	for {
		current, err := parser.readByte()
		if err != nil {
			return 0, err
		}
		if !isJSONSpace(current) {
			return current, nil
		}
	}
}

func (parser *requestJSONParser) readByte() (byte, error) {
	if parser.hasByte {
		parser.hasByte = false
		return parser.pending, nil
	}
	current, err := parser.reader.ReadByte()
	if err != nil {
		return 0, err
	}
	parser.bytesRead++
	if parser.bytesRead > MaxRequestBytes {
		return 0, errRequestSizeInvalid
	}
	return current, nil
}

func (parser *requestJSONParser) unreadByte(value byte) {
	parser.pending = value
	parser.hasByte = true
}

func (parser *requestJSONParser) publicError(err error) error {
	switch {
	case errors.Is(err, errRequestSizeInvalid), errors.Is(err, errRequestFields), errors.Is(err, errRequestUnknown), errors.Is(err, errRequestTrailing), errors.Is(err, errRequestNull):
		return err
	default:
		return errRequestJSONInvalid
	}
}

func (parser *requestJSONParser) stringReadError(err error) error {
	if errors.Is(err, errRequestSizeInvalid) {
		return err
	}
	return errRequestJSONInvalid
}

func isJSONSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\r'
}

type boundedBase64Decoder struct {
	encoded  [4 << 10]byte
	length   int
	output   []byte
	maximum  int
	finished bool
}

func (decoder *boundedBase64Decoder) write(value []byte) error {
	if decoder.finished {
		return errRequestJSONInvalid
	}
	for _, current := range value {
		if !isBase64Byte(current) {
			return errRequestJSONInvalid
		}
		decoder.encoded[decoder.length] = current
		decoder.length++
		if decoder.length == len(decoder.encoded) {
			if err := decoder.flush(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (decoder *boundedBase64Decoder) finish() ([]byte, error) {
	if decoder.length != 0 {
		if err := decoder.flush(); err != nil {
			return nil, err
		}
	}
	return decoder.output, nil
}

func (decoder *boundedBase64Decoder) flush() error {
	if decoder.length%4 != 0 {
		return errRequestJSONInvalid
	}
	var decoded [3 << 10]byte
	count, err := strictBase64.Decode(decoded[:], decoder.encoded[:decoder.length])
	if err != nil {
		return errRequestJSONInvalid
	}
	output, err := appendBounded(decoder.output, decoded[:count], decoder.maximum)
	if err != nil {
		return err
	}
	decoder.output = output
	if decoder.length >= 4 && (decoder.encoded[decoder.length-1] == '=' || decoder.encoded[decoder.length-2] == '=') {
		decoder.finished = true
	}
	decoder.length = 0
	return nil
}

func isBase64Byte(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '+' || value == '/' || value == '='
}

func appendBounded(destination, source []byte, maximum int) ([]byte, error) {
	if len(source) > maximum-len(destination) {
		return nil, errRequestFields
	}
	required := len(destination) + len(source)
	if required > cap(destination) {
		capacity := cap(destination) * 2
		if capacity < 4<<10 {
			capacity = 4 << 10
		}
		if capacity < required {
			capacity = required
		}
		if capacity > maximum {
			capacity = maximum
		}
		replacement := make([]byte, len(destination), capacity)
		copy(replacement, destination)
		destination = replacement
	}
	start := len(destination)
	destination = destination[:required]
	copy(destination[start:], source)
	return destination, nil
}

func (request Request) Validate() error {
	if request.SchemaVersion != SchemaVersion {
		return fmt.Errorf("vmguest: unsupported request schema %d", request.SchemaVersion)
	}
	if len(request.Args) > maxRequestArgs {
		return errors.New("vmguest: command argument list is invalid")
	}
	for _, arg := range request.Args {
		if strings.IndexByte(arg, 0) >= 0 || len(arg) > maxArgumentBytes {
			return errors.New("vmguest: command argument is invalid")
		}
	}
	switch request.Operation {
	case OperationProbe:
		if !request.hasOnlyDecodedFields(requestFieldSchemaVersion | requestFieldOperation) {
			return errors.New("vmguest: probe request fields are invalid")
		}
		if request.Path != "" || len(request.Args) != 0 || len(request.Data) != 0 || request.Mode != 0 || request.Action != "" {
			return errors.New("vmguest: probe request contains unrelated fields")
		}
	case OperationExecute:
		if !request.hasOnlyDecodedFields(requestFieldSchemaVersion | requestFieldOperation | requestFieldPath | requestFieldArgs) {
			return errors.New("vmguest: diagnostic request fields are invalid")
		}
		if len(request.Data) != 0 || request.Mode != 0 || request.Action != "" || !admittedDiagnostic(request.Path, request.Args) {
			return errors.New("vmguest: diagnostic command is not admitted")
		}
	case OperationPut:
		if !request.hasOnlyDecodedFields(requestFieldSchemaVersion | requestFieldOperation | requestFieldPath | requestFieldData | requestFieldMode) {
			return errors.New("vmguest: artifact request fields are invalid")
		}
		if !validRelativePath(request.Path) || len(request.Args) != 0 || len(request.Data) == 0 || len(request.Data) > MaxTransferBytes || (request.Mode != 0o600 && request.Mode != 0o644) || request.Action != "" {
			return errors.New("vmguest: artifact transfer is invalid")
		}
	case OperationDataWrite:
		if !request.hasOnlyDecodedFields(requestFieldSchemaVersion | requestFieldOperation | requestFieldPath | requestFieldData) {
			return errors.New("vmguest: persistent write request fields are invalid")
		}
		if !validRelativePath(request.Path) || len(request.Args) != 0 || len(request.Data) == 0 || len(request.Data) > MaxPersistentBytes || request.Mode != 0 || request.Action != "" {
			return errors.New("vmguest: persistent write is invalid")
		}
	case OperationDataRead:
		if !request.hasOnlyDecodedFields(requestFieldSchemaVersion | requestFieldOperation | requestFieldPath) {
			return errors.New("vmguest: persistent read request fields are invalid")
		}
		if !validRelativePath(request.Path) || len(request.Args) != 0 || len(request.Data) != 0 || request.Mode != 0 || request.Action != "" {
			return errors.New("vmguest: persistent read is invalid")
		}
	case OperationNetwork:
		if !request.hasOnlyDecodedFields(requestFieldSchemaVersion | requestFieldOperation | requestFieldPath | requestFieldData) {
			return errors.New("vmguest: network exchange request fields are invalid")
		}
		if !validNetworkEndpoint(request.Path) || len(request.Args) != 0 || len(request.Data) == 0 || len(request.Data) > MaxNetworkBytes || request.Mode != 0 || request.Action != "" {
			return errors.New("vmguest: network exchange is invalid")
		}
	case OperationStorage:
		if !request.hasOnlyDecodedFields(requestFieldSchemaVersion | requestFieldOperation | requestFieldAction) {
			return errors.New("vmguest: storage diagnostic request fields are invalid")
		}
		if request.Path != "" || len(request.Args) != 0 || len(request.Data) != 0 || request.Mode != 0 || !validStorageAction(request.Action) {
			return errors.New("vmguest: storage diagnostic action is invalid")
		}
	default:
		return errors.New("vmguest: operation is not admitted")
	}
	return nil
}

func validStorageAction(action StorageAction) bool {
	switch action {
	case StorageActionObserve, StorageActionProbeWrite, StorageActionFillENOSPC, StorageActionClearFill,
		StorageActionFSCKRepair, StorageActionFSCKCheck, StorageActionGrow:
		return true
	default:
		return false
	}
}

func (request Request) hasOnlyDecodedFields(expected uint8) bool {
	return request.decodedFields == 0 || request.decodedFields == expected
}

func validNetworkEndpoint(value string) bool {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || endpoint.Port() == 0 || endpoint.String() != value {
		return false
	}
	address := endpoint.Addr()
	return address.Is4() && address.IsPrivate() && !address.IsUnspecified() && !address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsMulticast()
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
		return len(args) == 3 && args[0] == "show" && admittedUnit(args[1]) && (args[2] == "--property=MainPID,ActiveState,SubState" || args[2] == "--property=MainPID,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus")
	case "/usr/bin/journalctl":
		return len(args) == 7 && args[0] == "--unit" && admittedUnit(args[1]) && strings.Join(args[2:], "\x00") == "--lines=20\x00--no-pager\x00--output=json\x00--output-fields=MESSAGE,PRIORITY\x00--boot"
	case "/usr/bin/readlink":
		return key == "/proc/1/exe"
	case "/usr/bin/stat":
		return key == "-fc\x00%T\x00/sys/fs/cgroup"
	case "/usr/bin/findmnt":
		return key == "-no\x00SOURCE,FSTYPE,TARGET\x00/var/lib/terrascale"
	case "/usr/bin/networkctl":
		return key == "status\x00eth0\x00--no-pager"
	case "/usr/bin/timedatectl":
		return key == "show\x00--property=NTPSynchronized\x00--value"
	case "/usr/bin/test":
		// Read-only existence probe for the engine's staged launch
		// configuration; readiness distinguishes an engine that awaits
		// control-plane delivery from one that fails to start.
		return key == "-s\x00/opt/terrascale/terrabase/current/terrabase.config"
	case "/usr/bin/uname":
		// Fixed-form architecture probe for the delivery lane's native
		// release selection.
		return key == "-m"
	case "/usr/bin/cat":
		// Fixed-form unit read: the delivery lane proves the activated
		// systemd unit text equals the qualified release's unit.
		return key == "/etc/systemd/system/terrascale-terrabase.service"
	case "/usr/bin/sha256sum":
		return len(args) == 1 && admittedDigestPath(args[0])
	default:
		return false
	}
}

func admittedUnit(value string) bool {
	return value == "terrascale-ts-node.service" || value == "terrascale-orchestrator.service" || value == "terrascale-terrabase.service"
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
