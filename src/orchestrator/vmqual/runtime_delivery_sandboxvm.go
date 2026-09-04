//go:build sandboxvm

package vmqual

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
	"terrascale.tech/orchestrator/src/orchestrator/vmguest"
)

const (
	deliveryComponent          = "terrabase"
	deliveryUnit               = "terrascale-terrabase.service"
	deliveryBinary             = "/opt/terrascale/terrabase/current/terrabase"
	deliveryPreviousBinary     = "/opt/terrascale/terrabase/previous/terrabase"
	deliveryUnitPath           = "/etc/systemd/system/terrascale-terrabase.service"
	deliveryPersistencePath    = "delivery/persistence.bin"
	deliveryReplyMaximumBytes  = 1 << 20
	deliveryCommandIDEntropy   = 12
	deliveryCommandWaitMaximum = 30 * time.Second
)

// activeDeliveryVM resolves a delivery host only through the factory's
// current ownership table. A stale name cannot address a deleted VM or a VM
// from another qualification run.
func (factory *firecrackerFactory) activeDeliveryVM(host string) (*sandboxVM, error) {
	if factory == nil || host == "" {
		return nil, errors.New("vmqual: delivery guest control is not configured")
	}
	if _, err := hostagent.NewNodeId(host); err != nil {
		return nil, errors.New("vmqual: delivery host identity is invalid")
	}
	factory.activeMu.Lock()
	defer factory.activeMu.Unlock()
	if factory.closed {
		return nil, errors.New("vmqual: delivery guest factory is closed")
	}
	vm := factory.active[host]
	if vm == nil || vm.id != host || vm.guest.ID != host {
		return nil, fmt.Errorf("vmqual: delivery host %s is not a participating guest", host)
	}
	return vm, nil
}

func newDeliveryCommandID(kind string) (string, error) {
	if kind == "" || strings.ContainsAny(kind, "_./ \\") {
		return "", errors.New("vmqual: delivery command kind is invalid")
	}
	entropy := make([]byte, deliveryCommandIDEntropy)
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("vmqual: generate delivery command ID: %w", err)
	}
	id := "vmq-" + kind + "-" + hex.EncodeToString(entropy)
	// Running the public constructor makes the command ID obey the same
	// closed vocabulary that ts-node durably journals inside the guest.
	if _, err := hostagent.NewNodeStatusRequest(id); err != nil {
		return "", fmt.Errorf("vmqual: generated delivery command ID: %w", err)
	}
	return id, nil
}

func deliveryRequestTimeout(ctx context.Context) time.Duration {
	timeout := deliveryCommandWaitMaximum
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return time.Millisecond
	}
	return timeout
}

// requestTSNode sends one typed command through the embedded NATS server.
// The adapter intentionally opens a short-lived client for each command: a
// response proves the currently running ts-node subscription rather than a
// cached local connection or an in-process callback.
func (factory *firecrackerFactory) requestTSNode(ctx context.Context, host, subject string, command, reply any) error {
	if ctx == nil {
		return errors.New("vmqual: delivery command context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := factory.activeDeliveryVM(host); err != nil {
		return err
	}
	services, ok := factory.services.(*qualificationRuntimeServices)
	if !ok || services == nil {
		return errors.New("vmqual: embedded qualification NATS is not configured")
	}
	services.mu.Lock()
	if services.closed || !services.started || services.nats == nil {
		services.mu.Unlock()
		return errors.New("vmqual: embedded qualification NATS is not running")
	}
	serverURL := services.nats.ClientURL()
	services.mu.Unlock()
	if serverURL == "" {
		return errors.New("vmqual: embedded qualification NATS has no client address")
	}
	payload, err := json.Marshal(command)
	if err != nil {
		return fmt.Errorf("vmqual: encode ts-node command: %w", err)
	}
	timeout := deliveryRequestTimeout(ctx)
	connection, err := nats.Connect(serverURL,
		nats.Name("vmqual-delivery-"+host),
		nats.Timeout(timeout),
		nats.NoReconnect(),
		nats.MaxPingsOutstanding(2),
	)
	if err != nil {
		return fmt.Errorf("vmqual: connect to embedded qualification NATS: %w", err)
	}
	defer connection.Close()
	message, err := connection.RequestWithContext(ctx, subject, payload)
	if err != nil {
		return fmt.Errorf("vmqual: request ts-node command for %s: %w", host, err)
	}
	if len(message.Data) == 0 || len(message.Data) > deliveryReplyMaximumBytes {
		return errors.New("vmqual: ts-node returned an invalid bounded reply")
	}
	if err := decodeDeliveryReply(message.Data, reply); err != nil {
		return fmt.Errorf("vmqual: decode ts-node reply for %s: %w", host, err)
	}
	return nil
}

func decodeDeliveryReply(data []byte, target any) error {
	if target == nil || len(data) == 0 || len(data) > deliveryReplyMaximumBytes {
		return errors.New("delivery reply is invalid")
	}
	if err := validateDeliveryJSONDocument(data); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return errors.New("delivery reply is not an object")
	}
	if detail, present := fields["detail"]; present && len(fields) == 1 {
		var text string
		if err := json.Unmarshal(detail, &text); err != nil || text == "" {
			return errors.New("ts-node returned an invalid command error")
		}
		return errors.New(text)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("delivery reply shape is invalid: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("delivery reply has trailing data")
	}
	return nil
}

// validateDeliveryJSONDocument rejects duplicate names at every nesting
// level before encoding/json fills a typed reply. DisallowUnknownFields then
// closes the vocabulary against the concrete hostagent reply type.
func validateDeliveryJSONDocument(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return errors.New("delivery reply is not valid JSON")
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return errors.New("delivery reply must be an object")
	}
	if err := validateDeliveryJSONObject(decoder, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("delivery reply has trailing data")
	}
	return nil
}

func validateDeliveryJSONObject(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("delivery reply nesting is excessive")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return errors.New("delivery reply field name is invalid")
		}
		name, ok := nameToken.(string)
		if !ok || name == "" {
			return errors.New("delivery reply field name is invalid")
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("delivery reply contains duplicate field %q", name)
		}
		seen[name] = struct{}{}
		value, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("delivery reply field %q is invalid", name)
		}
		if value == nil {
			return fmt.Errorf("delivery reply field %q must not be null", name)
		}
		if err := validateDeliveryJSONValue(decoder, value, depth+1); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errors.New("delivery reply object is incomplete")
	}
	return nil
}

func validateDeliveryJSONValue(decoder *json.Decoder, value json.Token, depth int) error {
	delimiter, compound := value.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		return validateDeliveryJSONObject(decoder, depth)
	case '[':
		if depth > 32 {
			return errors.New("delivery reply nesting is excessive")
		}
		for decoder.More() {
			item, err := decoder.Token()
			if err != nil || item == nil {
				return errors.New("delivery reply array contains an invalid value")
			}
			if err := validateDeliveryJSONValue(decoder, item, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("delivery reply array is incomplete")
		}
		return nil
	default:
		return errors.New("delivery reply contains an invalid delimiter")
	}
}

func (factory *firecrackerFactory) nodeStatus(ctx context.Context, host, kind string) (hostagent.NodeStatusReport, error) {
	nodeID, err := hostagent.NewNodeId(host)
	if err != nil {
		return hostagent.NodeStatusReport{}, err
	}
	commandID, err := newDeliveryCommandID(kind)
	if err != nil {
		return hostagent.NodeStatusReport{}, err
	}
	request, err := hostagent.NewNodeStatusRequest(commandID)
	if err != nil {
		return hostagent.NodeStatusReport{}, err
	}
	subject, err := hostagent.NodeDrainStatusSubject(nodeID)
	if err != nil {
		return hostagent.NodeStatusReport{}, err
	}
	var report hostagent.NodeStatusReport
	if err := factory.requestTSNode(ctx, host, subject, request, &report); err != nil {
		return hostagent.NodeStatusReport{}, err
	}
	if report.CommandId != commandID || report.NodeId != host || report.Facts.State != report.State {
		return hostagent.NodeStatusReport{}, errors.New("vmqual: ts-node status reply identity is inconsistent")
	}
	switch report.State {
	case hostagent.NodeStateServing:
		if report.Quiesced {
			return hostagent.NodeStatusReport{}, errors.New("vmqual: serving ts-node reported itself quiesced")
		}
	case hostagent.NodeStateDraining, hostagent.NodeStateQuiesced:
	default:
		return hostagent.NodeStatusReport{}, errors.New("vmqual: ts-node reported an unknown lifecycle state")
	}
	return report, nil
}

// Cordon uses ts-node's durable drain command and then obtains a separate
// status sample. A receipt alone is not accepted as proof of the resulting
// guest state.
func (factory *firecrackerFactory) Cordon(ctx context.Context, host string, cordoned bool) error {
	nodeID, err := hostagent.NewNodeId(host)
	if err != nil {
		return err
	}
	commandID, err := newDeliveryCommandID("cordon")
	if err != nil {
		return err
	}
	command, err := hostagent.NewDrainCommand(commandID, cordoned)
	if err != nil {
		return err
	}
	subject, err := hostagent.NodeDrainSubject(nodeID)
	if err != nil {
		return err
	}
	var receipt hostagent.DrainReceipt
	if err := factory.requestTSNode(ctx, host, subject, command, &receipt); err != nil {
		return err
	}
	if receipt.CommandId != commandID || receipt.NodeId != host || receipt.Draining != cordoned || !cordoned && receipt.Quiesced {
		return errors.New("vmqual: ts-node drain receipt does not describe the requested state")
	}
	report, err := factory.nodeStatus(ctx, host, "cordon-status")
	if err != nil {
		return err
	}
	observedCordoned := report.State == hostagent.NodeStateDraining || report.State == hostagent.NodeStateQuiesced
	if observedCordoned != cordoned {
		return errors.New("vmqual: ts-node drain state did not converge")
	}
	return nil
}

func (factory *firecrackerFactory) DrainStatus(ctx context.Context, host string) (delivery.DrainReport, error) {
	report, err := factory.nodeStatus(ctx, host, "drain-status")
	if err != nil {
		return delivery.DrainReport{}, err
	}
	cordoned := report.State == hostagent.NodeStateDraining || report.State == hostagent.NodeStateQuiesced
	return delivery.DrainReport{Cordoned: cordoned, Drained: cordoned && report.Quiesced}, nil
}

func statusComponent(report hostagent.NodeStatusReport, component string) (hostagent.ComponentFact, error) {
	var found *hostagent.ComponentFact
	for index := range report.Facts.Components {
		fact := report.Facts.Components[index]
		if fact.Name != component {
			continue
		}
		if found != nil {
			return hostagent.ComponentFact{}, fmt.Errorf("vmqual: ts-node returned duplicate %s facts", component)
		}
		copy := fact
		found = &copy
	}
	if found == nil {
		return hostagent.ComponentFact{}, fmt.Errorf("vmqual: ts-node did not report %s facts", component)
	}
	return *found, nil
}

func (factory *firecrackerFactory) versionForDeliveryDigest(component, digest string) (string, bool) {
	services, ok := factory.services.(*qualificationRuntimeServices)
	if !ok || services == nil {
		return "", false
	}
	want := strings.TrimPrefix(digest, "sha256:")
	services.mu.Lock()
	defer services.mu.Unlock()
	for _, artifact := range services.artifacts {
		if artifact.manifest.Component == component && artifact.manifest.SHA256 == want {
			return artifact.manifest.Version, true
		}
	}
	return "", false
}

// Converge accepts only the canonical runtime plan emitted by delivery. It
// asks ts-node to deploy a known, signed manifest version, or to roll back
// when the target digest is the guest's exact previous release. Digest-only
// plans that cannot be resolved to authenticated guest state fail closed.
func (factory *firecrackerFactory) Converge(ctx context.Context, host string, encodedPlan []byte) error {
	if ctx == nil {
		return errors.New("vmqual: delivery converge context is nil")
	}
	var plan runtimeplan.HostRuntimePlan
	if err := json.Unmarshal(encodedPlan, &plan); err != nil {
		return fmt.Errorf("vmqual: decode delivery runtime plan: %w", err)
	}
	if plan.AllocationId.Value != deliveryComponent || plan.Systemd == nil || plan.Systemd.UnitName != deliveryUnit {
		return errors.New("vmqual: delivery runtime plan is not the TerraBase systemd allocation")
	}
	targetDigest := "sha256:" + plan.ArtifactDigest.Value
	vm, err := factory.activeDeliveryVM(host)
	if err != nil {
		return err
	}
	report, err := factory.nodeStatus(ctx, host, "converge-status")
	if err != nil {
		return err
	}
	if !report.Quiesced || report.State == hostagent.NodeStateServing {
		return errors.New("vmqual: ts-node refused converge before the guest drained")
	}
	currentDigest, err := deliveryGuestFileDigest(ctx, vm, deliveryBinary)
	if err == nil && delivery.SameDigest(currentDigest, targetDigest) {
		return nil
	}

	nodeID, err := hostagent.NewNodeId(host)
	if err != nil {
		return err
	}
	var receipt hostagent.DeployReceipt
	if version, known := factory.versionForDeliveryDigest(deliveryComponent, targetDigest); known {
		commandID, idErr := newDeliveryCommandID("deploy")
		if idErr != nil {
			return idErr
		}
		command, commandErr := hostagent.NewDeployCommand(commandID, deliveryComponent, version)
		if commandErr != nil {
			return commandErr
		}
		subject, subjectErr := hostagent.NodeDeploySubject(nodeID)
		if subjectErr != nil {
			return subjectErr
		}
		if err := factory.requestTSNode(ctx, host, subject, command, &receipt); err != nil {
			return err
		}
		if receipt.CommandId != commandID || receipt.NodeId != host || !receipt.Accepted || receipt.Current != version {
			return errors.New("vmqual: ts-node did not accept the exact signed release")
		}
	} else {
		previousDigest, previousErr := deliveryGuestFileDigest(ctx, vm, deliveryPreviousBinary)
		if previousErr != nil || !delivery.SameDigest(previousDigest, targetDigest) {
			return errors.New("vmqual: delivery plan digest has no authenticated guest release")
		}
		commandID, idErr := newDeliveryCommandID("rollback")
		if idErr != nil {
			return idErr
		}
		command, commandErr := hostagent.NewRollbackCommand(commandID, deliveryComponent)
		if commandErr != nil {
			return commandErr
		}
		subject, subjectErr := hostagent.NodeRollbackSubject(nodeID)
		if subjectErr != nil {
			return subjectErr
		}
		if err := factory.requestTSNode(ctx, host, subject, command, &receipt); err != nil {
			return err
		}
		if receipt.CommandId != commandID || receipt.NodeId != host || !receipt.Accepted {
			return errors.New("vmqual: ts-node did not accept the exact rollback release")
		}
	}
	observedDigest, err := deliveryGuestFileDigest(ctx, vm, deliveryBinary)
	if err != nil {
		return err
	}
	if !delivery.SameDigest(observedDigest, targetDigest) {
		return errors.New("vmqual: guest current release differs from the converged digest")
	}
	return nil
}

func deliveryGuestCommand(ctx context.Context, vm *sandboxVM, path string, args ...string) (vmguest.CommandResult, error) {
	if vm == nil || !filepath.IsAbs(path) || len(args) > 3 {
		return vmguest.CommandResult{}, errors.New("vmqual: delivery guest command is invalid")
	}
	response, err := vm.guestRequest(ctx, vmguest.Request{
		SchemaVersion: vmguest.SchemaVersion,
		Operation:     vmguest.OperationExecute,
		Path:          path,
		Args:          append([]string(nil), args...),
	})
	if err != nil {
		return vmguest.CommandResult{}, err
	}
	if response.Command == nil {
		return vmguest.CommandResult{}, errors.New("vmqual: delivery guest command result is missing")
	}
	result := *response.Command
	if result.ExitCode != 0 || result.Error != "" || result.StdoutTruncated || result.StderrTruncated || len(result.Stderr) != 0 {
		return vmguest.CommandResult{}, &GuestCommandError{ExitCode: result.ExitCode, RemoteError: result.Error, StdoutTruncated: result.StdoutTruncated, StderrTruncated: result.StderrTruncated}
	}
	return result, nil
}

func deliveryGuestFileDigest(ctx context.Context, vm *sandboxVM, path string) (string, error) {
	result, err := deliveryGuestCommand(ctx, vm, "/usr/bin/sha256sum", path)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(result.Stdout))
	if len(fields) != 2 || fields[1] != path || len(fields[0]) != 64 || fields[0] != strings.ToLower(fields[0]) {
		return "", errors.New("vmqual: guest returned an invalid file digest observation")
	}
	if _, err := hex.DecodeString(fields[0]); err != nil {
		return "", errors.New("vmqual: guest returned a non-hex file digest observation")
	}
	return "sha256:" + fields[0], nil
}

func canonicalDeliveryDigest(digest string) bool {
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 || digest != strings.ToLower(digest) {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	return err == nil
}

func deliveryGuestUnitActive(ctx context.Context, vm *sandboxVM) (bool, error) {
	result, err := deliveryGuestCommand(ctx, vm, "/usr/bin/systemctl", "is-active", deliveryUnit)
	if err != nil {
		var commandErr *GuestCommandError
		if errors.As(err, &commandErr) && !commandErr.StdoutTruncated && !commandErr.StderrTruncated {
			return false, nil
		}
		return false, err
	}
	return strings.TrimSpace(string(result.Stdout)) == "active", nil
}

func deliveryNativeArchitecture(ctx context.Context, vm *sandboxVM) (string, error) {
	result, err := deliveryGuestCommand(ctx, vm, "/usr/bin/uname", "-m")
	if err != nil {
		return "", err
	}
	switch strings.TrimSpace(string(result.Stdout)) {
	case "x86_64":
		return "linux/amd64", nil
	case "aarch64":
		return "linux/arm64", nil
	default:
		return "", errors.New("vmqual: guest reported an unsupported native architecture")
	}
}

// QualifyTSNode accepts no coordinator-synthesized evidence. It first proves
// that the qualification input names the same signing authority and exact
// executable already served by the Region-local release service. The
// current delivery contract generates an unrelated private release and omits
// its prior artifact; that input therefore fails here instead of being
// represented as a successful guest install.
func (factory *firecrackerFactory) QualifyTSNode(ctx context.Context, host string, qualification TSNodeGuestQualification) (TSNodeGuestObservation, error) {
	var observation TSNodeGuestObservation
	if ctx == nil {
		return observation, errors.New("vmqual: ts-node qualification context is nil")
	}
	if digest, err := ValidateDeliveryArchitectureManifest(qualification.Manifest, qualification.Candidates, qualification.PublicKey); err != nil {
		return observation, err
	} else if !delivery.SameDigest(digest, qualification.ManifestDigest) {
		return observation, errors.New("vmqual: ts-node qualification manifest digest is inconsistent")
	}
	vm, err := factory.activeDeliveryVM(host)
	if err != nil {
		return observation, err
	}
	native, err := deliveryNativeArchitecture(ctx, vm)
	if err != nil {
		return observation, err
	}
	candidate, present := qualification.Candidates[native]
	if !present {
		return observation, errors.New("vmqual: ts-node qualification omitted the native artifact")
	}
	services, ok := factory.services.(*qualificationRuntimeServices)
	if !ok || services == nil {
		return observation, errors.New("vmqual: signed qualification release service is missing")
	}
	services.mu.Lock()
	sameAuthority := ed25519.PublicKey(services.publicKey).Equal(qualification.PublicKey)
	servedCandidate := false
	for _, artifact := range services.artifacts {
		if artifact.manifest.Component == deliveryComponent &&
			artifact.manifest.SHA256 == strings.TrimPrefix(candidate.Identity.Digest, "sha256:") &&
			bytes.Equal(artifact.binary, candidate.Body) && bytes.Equal(artifact.signature, candidate.Signature) {
			servedCandidate = true
		}
	}
	services.mu.Unlock()
	if !sameAuthority || !servedCandidate {
		return observation, errors.New("vmqual: delivery qualification does not expose an executable signed by the guest's pinned release authority")
	}

	installedDigest, err := deliveryGuestFileDigest(ctx, vm, deliveryBinary)
	if err != nil {
		return observation, err
	}
	active, err := deliveryGuestUnitActive(ctx, vm)
	if err != nil {
		return observation, err
	}
	unitResult, err := deliveryGuestCommand(ctx, vm, "/usr/bin/cat", deliveryUnitPath)
	if err != nil {
		return observation, err
	}
	if !active || !delivery.SameDigest(installedDigest, candidate.Identity.Digest) || string(unitResult.Stdout) != qualification.ExpectedSystemdUnit {
		return observation, errors.New("vmqual: guest did not activate the exact qualified systemd release")
	}
	if err := vm.DataWrite(ctx, deliveryPersistencePath, qualification.PersistenceSentinel); err != nil {
		return observation, err
	}
	before, err := vm.DataRead(ctx, deliveryPersistencePath)
	if err != nil || !bytes.Equal(before, qualification.PersistenceSentinel) {
		return observation, errors.New("vmqual: guest did not persist the delivery sentinel before restart")
	}
	if err := vm.Stop(ctx); err != nil {
		return observation, fmt.Errorf("vmqual: stop delivery qualification guest: %w", err)
	}
	if err := vm.StartReady(ctx); err != nil {
		return observation, fmt.Errorf("vmqual: restart delivery qualification guest: %w", err)
	}
	after, err := vm.DataRead(ctx, deliveryPersistencePath)
	if err != nil || !bytes.Equal(after, qualification.PersistenceSentinel) {
		return observation, errors.New("vmqual: guest delivery sentinel did not survive restart")
	}
	// The interface supplies no versions/routes for the two deliberately bad
	// releases, so no ts-node install command can address them. Absence is not
	// rejection evidence; fail closed instead of manufacturing attempts.
	return observation, errors.New("vmqual: delivery qualification lacks addressable bad-signature and bad-digest release versions")
}

func (factory *firecrackerFactory) observeDeliveryRuntime(ctx context.Context, host string) (*sandboxVM, hostagent.NodeStatusReport, hostagent.ComponentFact, string, bool, error) {
	vm, err := factory.activeDeliveryVM(host)
	if err != nil {
		return nil, hostagent.NodeStatusReport{}, hostagent.ComponentFact{}, "", false, err
	}
	report, err := factory.nodeStatus(ctx, host, "observe")
	if err != nil {
		return nil, hostagent.NodeStatusReport{}, hostagent.ComponentFact{}, "", false, err
	}
	fact, err := statusComponent(report, deliveryComponent)
	if err != nil {
		return nil, hostagent.NodeStatusReport{}, hostagent.ComponentFact{}, "", false, err
	}
	digest, err := deliveryGuestFileDigest(ctx, vm, deliveryBinary)
	if err != nil {
		return nil, hostagent.NodeStatusReport{}, hostagent.ComponentFact{}, "", false, err
	}
	active, err := deliveryGuestUnitActive(ctx, vm)
	if err != nil {
		return nil, hostagent.NodeStatusReport{}, hostagent.ComponentFact{}, "", false, err
	}
	if fact.UnitActive != active {
		return nil, hostagent.NodeStatusReport{}, hostagent.ComponentFact{}, "", false, errors.New("vmqual: ts-node facts disagree with guest systemd state")
	}
	return vm, report, fact, digest, active, nil
}

func (factory *firecrackerFactory) CheckDeliveryGate(ctx context.Context, host, digest, gate string) (DeliveryGuestGateObservation, error) {
	observation := DeliveryGuestGateObservation{Host: host, Digest: digest, Gate: gate}
	if !canonicalDeliveryDigest(digest) {
		return observation, errors.New("vmqual: delivery gate digest is invalid")
	}
	_, report, _, activeDigest, active, err := factory.observeDeliveryRuntime(ctx, host)
	if err != nil {
		return observation, err
	}
	if !delivery.SameDigest(activeDigest, digest) || !active {
		return observation, errors.New("vmqual: delivery gate observed the wrong or inactive release")
	}
	switch gate {
	case "process-health":
		observation.Passed = true
		return observation, nil
	case "external-health":
		// A direct systemd observation and a separately sampled ts-node fact
		// prove process state, not the external TerraBase API. The current VM
		// contract has no service health endpoint, so it must not pass here.
		return observation, errors.New("vmqual: no guest external-health probe is configured")
	case deliveryContractFailureGate:
		if !report.Quiesced {
			return observation, errors.New("vmqual: catch-up gate ran outside the drained state")
		}
		return observation, errors.New("vmqual: no guest replication and backup catch-up observation is configured")
	default:
		return observation, fmt.Errorf("vmqual: delivery gate %q is not admitted", gate)
	}
}

func (factory *firecrackerFactory) ObserveDeliveryGuest(ctx context.Context, host string) (DeliveryGuestObservation, error) {
	observation := DeliveryGuestObservation{Host: host}
	vm, report, _, digest, active, err := factory.observeDeliveryRuntime(ctx, host)
	if err != nil {
		return observation, err
	}
	observation.ActiveDigest = digest
	observation.Cordoned = report.State == hostagent.NodeStateDraining || report.State == hostagent.NodeStateQuiesced
	observation.UnitActive = active
	if host == deliveryContractCanary {
		persistent, err := vm.DataRead(ctx, deliveryPersistencePath)
		if err != nil {
			return observation, fmt.Errorf("vmqual: read delivery persistence observation: %w", err)
		}
		observation.PersistentData = persistent
	}
	return observation, nil
}

var _ DeliveryGuestControl = (*firecrackerFactory)(nil)
