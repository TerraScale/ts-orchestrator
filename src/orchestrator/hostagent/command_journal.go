package hostagent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const (
	commandJournalVersion      = 1
	commandJournalMaximumBytes = 64 << 20
	commandJournalMaximumItems = 2048
	commandJournalMaximumWire  = 2 << 20
	commandJournalPending      = "pending"
	commandJournalDone         = "done"
)

type commandJournalRecord struct {
	Sequence  uint64          `json:"sequence"`
	CommandId string          `json:"commandId"`
	Kind      string          `json:"kind"`
	Request   []byte          `json:"request"`
	Plan      *transitionPlan `json:"plan,omitempty"`
	State     string          `json:"state"`
	Response  []byte          `json:"response,omitempty"`
}

type commandJournalDocument struct {
	Version      int                    `json:"version"`
	NextSequence uint64                 `json:"nextSequence"`
	Records      []commandJournalRecord `json:"records"`
}

// commandJournal is the root-owned write-ahead log for command execution.
// A pending transition contains its fixed version plan, and a done record
// contains the exact response bytes returned for every later redelivery.
type commandJournal struct {
	dir  string
	path string
}

func newCommandJournal(dir string) (*commandJournal, error) {
	if !safeAbsolutePath(dir) {
		return nil, &InvalidOperationError{Message: "The command journal directory must be an absolute safe path."}
	}
	return &commandJournal{dir: dir, path: filepath.Join(dir, "commands.json")}, nil
}

func (j *commandJournal) initialize() error {
	if err := ensureDirectory(j.dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(j.dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(j.dir)
	if err != nil {
		return err
	}
	if err := requireOwnedDirectory(info, "command journal directory"); err != nil {
		return err
	}
	for _, directory := range []string{j.dir, filepath.Dir(j.dir), filepath.Dir(filepath.Dir(j.dir))} {
		if err := syncDir(directory); err != nil {
			return err
		}
	}
	_, err = j.load()
	return err
}

func (j *commandJournal) find(kind, commandId string, request []byte) (commandJournalRecord, bool, error) {
	document, err := j.load()
	if err != nil {
		return commandJournalRecord{}, false, err
	}
	for _, record := range document.Records {
		if record.CommandId != commandId {
			continue
		}
		if record.Kind != kind || !bytes.Equal(record.Request, request) {
			return commandJournalRecord{}, false, &InvalidOperationError{Message: fmt.Sprintf(
				"Command ID %s was already used for a different command.", commandId)}
		}
		return record, true, nil
	}
	return commandJournalRecord{}, false, nil
}

func (j *commandJournal) begin(kind, commandId string, request []byte, plan *transitionPlan) (commandJournalRecord, error) {
	document, err := j.load()
	if err != nil {
		return commandJournalRecord{}, err
	}
	for _, record := range document.Records {
		if record.CommandId != commandId {
			continue
		}
		if record.Kind != kind || !bytes.Equal(record.Request, request) {
			return commandJournalRecord{}, &InvalidOperationError{Message: fmt.Sprintf(
				"Command ID %s was already used for a different command.", commandId)}
		}
		return record, nil
	}
	record := commandJournalRecord{
		Sequence:  document.NextSequence,
		CommandId: commandId,
		Kind:      kind,
		Request:   append([]byte(nil), request...),
		Plan:      cloneTransitionPlan(plan),
		State:     commandJournalPending,
	}
	document.NextSequence++
	document.Records = append(document.Records, record)
	if err := fitCommandJournal(&document, record.Sequence); err != nil {
		return commandJournalRecord{}, err
	}
	if err := j.persist(document); err != nil {
		return commandJournalRecord{}, err
	}
	return record, nil
}

func (j *commandJournal) storeDone(kind, commandId string, request, response []byte) (commandJournalRecord, error) {
	document, err := j.load()
	if err != nil {
		return commandJournalRecord{}, err
	}
	for _, record := range document.Records {
		if record.CommandId != commandId {
			continue
		}
		if record.Kind != kind || !bytes.Equal(record.Request, request) {
			return commandJournalRecord{}, &InvalidOperationError{Message: fmt.Sprintf(
				"Command ID %s was already used for a different command.", commandId)}
		}
		return record, nil
	}
	record := commandJournalRecord{
		Sequence:  document.NextSequence,
		CommandId: commandId,
		Kind:      kind,
		Request:   append([]byte(nil), request...),
		State:     commandJournalDone,
		Response:  append([]byte(nil), response...),
	}
	document.NextSequence++
	document.Records = append(document.Records, record)
	if err := fitCommandJournal(&document, record.Sequence); err != nil {
		return commandJournalRecord{}, err
	}
	if err := j.persist(document); err != nil {
		return commandJournalRecord{}, err
	}
	return record, nil
}

func (j *commandJournal) complete(record commandJournalRecord, response []byte) error {
	document, err := j.load()
	if err != nil {
		return err
	}
	for index := range document.Records {
		current := &document.Records[index]
		if current.Sequence != record.Sequence {
			continue
		}
		if current.CommandId != record.CommandId || current.Kind != record.Kind ||
			!bytes.Equal(current.Request, record.Request) {
			return &InvalidDataError{Message: "The command journal record identity changed."}
		}
		if current.State == commandJournalDone {
			if bytes.Equal(current.Response, response) {
				return nil
			}
			return &InvalidOperationError{Message: "A completed command receipt is immutable."}
		}
		current.State = commandJournalDone
		current.Plan = nil
		current.Response = append([]byte(nil), response...)
		if err := fitCommandJournal(&document, current.Sequence); err != nil {
			return err
		}
		return j.persist(document)
	}
	return &InvalidDataError{Message: "The pending command journal record is missing."}
}

func (j *commandJournal) pending() ([]commandJournalRecord, error) {
	document, err := j.load()
	if err != nil {
		return nil, err
	}
	var pending []commandJournalRecord
	for _, record := range document.Records {
		if record.State == commandJournalPending {
			pending = append(pending, record)
		}
	}
	return pending, nil
}

func (j *commandJournal) latestDrain() (DrainCommand, bool, error) {
	document, err := j.load()
	if err != nil {
		return DrainCommand{}, false, err
	}
	var latest commandJournalRecord
	found := false
	for _, record := range document.Records {
		if record.Kind == commandKindDrain && (!found || record.Sequence > latest.Sequence) {
			latest = record
			found = true
		}
	}
	if !found {
		return DrainCommand{}, false, nil
	}
	command, err := decodeDrainCommand(latest.Request)
	if err != nil {
		return DrainCommand{}, false, err
	}
	return command, true, nil
}

func (j *commandJournal) load() (commandJournalDocument, error) {
	document := commandJournalDocument{Version: commandJournalVersion, NextSequence: 1}
	data, info, err := readRegularFileBoundedInfo(j.path, commandJournalMaximumBytes)
	if os.IsNotExist(err) {
		return document, nil
	}
	if err != nil {
		return commandJournalDocument{}, err
	}
	if err := requireOwnedRegular(info, false, "command journal"); err != nil {
		return commandJournalDocument{}, err
	}
	if info.Mode().Perm() != 0o600 {
		return commandJournalDocument{}, &InvalidDataError{Message: "The command journal must have mode 0600."}
	}
	document, err = decodeCommandJournalDocument(data)
	if err != nil {
		return commandJournalDocument{}, err
	}
	if err := validateCommandJournal(document); err != nil {
		return commandJournalDocument{}, err
	}
	return document, nil
}

func decodeCommandJournalDocument(data []byte) (commandJournalDocument, error) {
	fields, err := decodeJournalObject(data, commandJournalMaximumBytes,
		[]string{"version", "nextSequence", "records"}, nil)
	if err != nil {
		return commandJournalDocument{}, err
	}
	var document commandJournalDocument
	if json.Unmarshal(fields["version"], &document.Version) != nil ||
		json.Unmarshal(fields["nextSequence"], &document.NextSequence) != nil {
		return commandJournalDocument{}, &InvalidDataError{Message: "The command journal header has invalid field types."}
	}
	var records []json.RawMessage
	if err := json.Unmarshal(fields["records"], &records); err != nil || records == nil {
		return commandJournalDocument{}, &InvalidDataError{Message: "The command journal records field is invalid."}
	}
	if len(records) > commandJournalMaximumItems {
		return commandJournalDocument{}, &InvalidDataError{Message: "The command journal has too many records."}
	}
	document.Records = make([]commandJournalRecord, 0, len(records))
	for _, raw := range records {
		record, err := decodeCommandJournalRecord(raw)
		if err != nil {
			return commandJournalDocument{}, err
		}
		document.Records = append(document.Records, record)
	}
	return document, nil
}

func decodeCommandJournalRecord(data []byte) (commandJournalRecord, error) {
	fields, err := decodeJournalObject(data, commandJournalMaximumWire*4,
		[]string{"sequence", "commandId", "kind", "request", "state"},
		[]string{"plan", "response"})
	if err != nil {
		return commandJournalRecord{}, err
	}
	var record commandJournalRecord
	if json.Unmarshal(fields["sequence"], &record.Sequence) != nil ||
		json.Unmarshal(fields["commandId"], &record.CommandId) != nil ||
		json.Unmarshal(fields["kind"], &record.Kind) != nil ||
		json.Unmarshal(fields["request"], &record.Request) != nil ||
		json.Unmarshal(fields["state"], &record.State) != nil {
		return commandJournalRecord{}, &InvalidDataError{Message: "The command journal record has invalid field types."}
	}
	if raw, present := fields["response"]; present {
		if err := json.Unmarshal(raw, &record.Response); err != nil {
			return commandJournalRecord{}, &InvalidDataError{Message: "The command journal response is invalid."}
		}
	}
	if raw, present := fields["plan"]; present {
		plan, err := decodeTransitionPlan(raw)
		if err != nil {
			return commandJournalRecord{}, err
		}
		record.Plan = &plan
	}
	return record, nil
}

func decodeTransitionPlan(data []byte) (transitionPlan, error) {
	fields, err := decodeJournalObject(data, commandJournalMaximumWire*2,
		[]string{"spec", "expectedSha256"}, nil)
	if err != nil {
		return transitionPlan{}, err
	}
	specFields := []string{
		"name", "version", "artifactUrl", "signatureUrl", "sha256", "user",
		"dataVolume", "cpuWeight", "memoryMaxBytes", "ioWeight", "needsNetlink",
	}
	if _, err := decodeJournalObject(fields["spec"], commandJournalMaximumWire, specFields, nil); err != nil {
		return transitionPlan{}, err
	}
	var plan transitionPlan
	if json.Unmarshal(fields["spec"], &plan.Spec) != nil ||
		json.Unmarshal(fields["expectedSha256"], &plan.ExpectedSha256) != nil {
		return transitionPlan{}, &InvalidDataError{Message: "The command journal transition plan is invalid."}
	}
	return plan, nil
}

func decodeJournalObject(data []byte, maximum int, required, optional []string) (map[string]json.RawMessage, error) {
	if len(data) == 0 || len(data) > maximum {
		return nil, &InvalidDataError{Message: "The command journal object exceeds its size bound."}
	}
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, field := range required {
		allowed[field] = struct{}{}
	}
	for _, field := range optional {
		allowed[field] = struct{}{}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, &InvalidDataError{Message: "The command journal value must be an object."}
	}
	fields := make(map[string]json.RawMessage, len(allowed))
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, &InvalidDataError{Message: "The command journal field name is invalid."}
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, &InvalidDataError{Message: "The command journal field name is invalid."}
		}
		if _, known := allowed[key]; !known {
			return nil, &InvalidDataError{Message: fmt.Sprintf("The command journal contains unknown field %q.", key)}
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, &InvalidDataError{Message: fmt.Sprintf("The command journal contains duplicate field %q.", key)}
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, &InvalidDataError{Message: fmt.Sprintf("The command journal field %q is invalid.", key)}
		}
		fields[key] = raw
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, &InvalidDataError{Message: "The command journal object is incomplete."}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, &InvalidDataError{Message: "The command journal object has trailing data."}
	}
	for _, field := range required {
		if _, present := fields[field]; !present {
			return nil, &InvalidDataError{Message: fmt.Sprintf("The command journal is missing field %q.", field)}
		}
	}
	return fields, nil
}

func validateCommandJournal(document commandJournalDocument) error {
	if document.Version != commandJournalVersion || document.NextSequence == 0 ||
		len(document.Records) > commandJournalMaximumItems {
		return &InvalidDataError{Message: "The command journal header is invalid."}
	}
	ids := make(map[string]struct{}, len(document.Records))
	sequences := make(map[uint64]struct{}, len(document.Records))
	for _, record := range document.Records {
		if _, err := requireHostAgentToken(record.CommandId, "commandId", "The journal command ID is invalid."); err != nil {
			return &InvalidDataError{Message: "The command journal contains an invalid command ID."}
		}
		if !knownCommandKind(record.Kind) || record.Sequence == 0 || record.Sequence >= document.NextSequence ||
			len(record.Request) == 0 || len(record.Request) > commandJournalMaximumWire ||
			len(record.Response) > commandJournalMaximumWire {
			return &InvalidDataError{Message: "The command journal contains an invalid record."}
		}
		if _, exists := ids[record.CommandId]; exists {
			return &InvalidDataError{Message: "The command journal contains a duplicate command ID."}
		}
		if _, exists := sequences[record.Sequence]; exists {
			return &InvalidDataError{Message: "The command journal contains a duplicate sequence."}
		}
		ids[record.CommandId] = struct{}{}
		sequences[record.Sequence] = struct{}{}
		if err := validateJournalRequest(record); err != nil {
			return err
		}
		switch record.State {
		case commandJournalPending:
			if len(record.Response) != 0 {
				return &InvalidDataError{Message: "A pending command journal record has a response."}
			}
		case commandJournalDone:
			if len(record.Response) == 0 || record.Plan != nil {
				return &InvalidDataError{Message: "A completed command journal record is invalid."}
			}
		default:
			return &InvalidDataError{Message: "The command journal contains an invalid state."}
		}
		if (record.Kind == commandKindDeploy || record.Kind == commandKindRollback) == (record.Plan == nil) && record.State == commandJournalPending {
			return &InvalidDataError{Message: "The command journal transition plan is invalid."}
		}
		if record.Plan != nil {
			if _, err := NewComponentSpec(record.Plan.Spec); err != nil {
				return &InvalidDataError{Message: "The command journal component spec is invalid."}
			}
			switch record.Kind {
			case commandKindDeploy:
				if record.Plan.ExpectedSha256 != record.Plan.Spec.Sha256 {
					return &InvalidDataError{Message: "The journal deploy digest is invalid."}
				}
			case commandKindRollback:
				if record.Plan.ExpectedSha256 != "" {
					return &InvalidDataError{Message: "The journal rollback digest must come from installed metadata."}
				}
			}
		}
	}
	return nil
}

func validateJournalRequest(record commandJournalRecord) error {
	var commandId string
	var canonical []byte
	switch record.Kind {
	case commandKindDrain:
		command, err := decodeDrainCommand(record.Request)
		if err != nil {
			return &InvalidDataError{Message: "The journal drain request is invalid."}
		}
		commandId = command.CommandId
		canonical, _ = json.Marshal(command)
	case commandKindStatus:
		command, err := decodeStatusCommand(record.Request)
		if err != nil {
			return &InvalidDataError{Message: "The journal status request is invalid."}
		}
		commandId = command.CommandId
		canonical, _ = json.Marshal(command)
	case commandKindDeploy:
		command, err := decodeDeployCommand(record.Request)
		if err != nil {
			return &InvalidDataError{Message: "The journal deploy request is invalid."}
		}
		commandId = command.CommandId
		canonical, _ = json.Marshal(command)
		if record.State == commandJournalPending && record.Plan != nil &&
			(record.Plan.Spec.Name != command.Component || record.Plan.Spec.Version != command.Version) {
			return &InvalidDataError{Message: "The journal deploy plan does not match its request."}
		}
	case commandKindRollback:
		command, err := decodeRollbackCommand(record.Request)
		if err != nil {
			return &InvalidDataError{Message: "The journal rollback request is invalid."}
		}
		commandId = command.CommandId
		canonical, _ = json.Marshal(command)
		if record.State == commandJournalPending && record.Plan != nil && record.Plan.Spec.Name != command.Component {
			return &InvalidDataError{Message: "The journal rollback plan does not match its request."}
		}
	case commandKindManifest:
		command, err := decodeApplyManifestCommand(record.Request)
		if err != nil {
			return &InvalidDataError{Message: "The journal apply-manifest request is invalid."}
		}
		commandId = command.CommandId
		canonical, _ = json.Marshal(command)
	}
	if commandId != record.CommandId || !bytes.Equal(canonical, record.Request) {
		return &InvalidDataError{Message: "The journal command identity does not match its request."}
	}
	return nil
}

func knownCommandKind(kind string) bool {
	switch kind {
	case commandKindDrain, commandKindStatus, commandKindDeploy, commandKindRollback, commandKindManifest:
		return true
	default:
		return false
	}
}

func fitCommandJournal(document *commandJournalDocument, protectedSequence uint64) error {
	for {
		encoded, err := json.Marshal(document)
		if err != nil {
			return err
		}
		if len(document.Records) <= commandJournalMaximumItems && len(encoded) <= commandJournalMaximumBytes {
			return nil
		}
		removed := false
		for index, record := range document.Records {
			// Mutation receipts are permanent replay fences. Only status
			// records written by older builds may be discarded.
			if record.Kind != commandKindStatus || record.State != commandJournalDone || record.Sequence == protectedSequence {
				continue
			}
			document.Records = append(document.Records[:index], document.Records[index+1:]...)
			removed = true
			break
		}
		if !removed {
			return &InvalidOperationError{Message: "The command journal has no removable receipt within its size bound."}
		}
	}
}

func (j *commandJournal) persist(document commandJournalDocument) error {
	data, err := json.Marshal(document)
	if err != nil {
		return err
	}
	if len(data) > commandJournalMaximumBytes {
		return &InvalidOperationError{Message: "The command journal exceeds its size bound."}
	}
	file, err := os.OpenFile(filepath.Join(j.dir, ".commands.staging"),
		os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if os.IsExist(err) {
		info, statErr := os.Lstat(filepath.Join(j.dir, ".commands.staging"))
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return &InvalidOperationError{Message: "The command journal staging path is unsafe."}
		}
		if removeErr := os.Remove(filepath.Join(j.dir, ".commands.staging")); removeErr != nil {
			return removeErr
		}
		file, err = os.OpenFile(filepath.Join(j.dir, ".commands.staging"),
			os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	}
	if err != nil {
		return err
	}
	staged := file.Name()
	cleanup := func(cause error) error {
		return errors.Join(cause, file.Close(), os.Remove(staged))
	}
	if _, err := file.Write(data); err != nil {
		return cleanup(err)
	}
	if err := file.Sync(); err != nil {
		return cleanup(err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(staged)
		return err
	}
	if err := os.Rename(staged, j.path); err != nil {
		_ = os.Remove(staged)
		return err
	}
	return syncDir(j.dir)
}

func cloneTransitionPlan(plan *transitionPlan) *transitionPlan {
	if plan == nil {
		return nil
	}
	copy := *plan
	return &copy
}
