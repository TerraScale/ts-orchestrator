package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"math"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

const nodeOperationExecutionLifetime = 30 * time.Minute

func nodeOperationExecutionDeadline(envelope protocol.Envelope, request nodeOpRequest) (time.Time, error) {
	deadline := request.ExecutionDeadline
	if envelope.IssuedAt.IsZero() || deadline.IsZero() || !deadline.After(envelope.IssuedAt) || deadline.After(envelope.IssuedAt.Add(nodeOperationExecutionLifetime)) {
		return time.Time{}, errors.New("node operation lacks its original signed execution deadline")
	}
	return deadline, nil
}

type nodeOperationPolicyPins struct {
	ControllerSHA256 string `json:"controller_sha256"`
	RootSHA256       string `json:"root_sha256"`
	SpecSHA256       string `json:"spec_sha256"`
	RootRevision     uint64 `json:"root_revision"`
	SpecRevision     uint64 `json:"spec_revision"`
}

type nodeOperationRequestRecord struct {
	Wire   []byte                  `json:"wire"`
	Policy nodeOperationPolicyPins `json:"policy"`
}

type nodeOperationRequestReference struct {
	SHA256   string
	Revision uint64
}

func nodeOperationRequestKey(id string) string { return "nodeop.request." + id }

func nodeOperationPins(snapshot rootResourceSnapshot) nodeOperationPolicyPins {
	return nodeOperationPolicyPins{ControllerSHA256: snapshot.configDigest, RootSHA256: controllerSHA256(snapshot.rootWire),
		SpecSHA256: controllerSHA256(snapshot.specWire), RootRevision: snapshot.rootRevision, SpecRevision: snapshot.specRevision}
}

func nodeOperationPolicy(cfg Config, snapshot rootResourceSnapshot) (signerPolicy, error) {
	if snapshot.services == nil || snapshot.rootRevision == 0 || snapshot.specRevision == 0 || len(snapshot.rootWire) == 0 || len(snapshot.specWire) == 0 {
		return signerPolicy{}, errors.New("node operation requires current independently signed policy sources")
	}
	cfg.Controller.TrustedSigners = snapshot.services.effectiveSigners(snapshot.services.current)
	return buildSignerPolicy(cfg)
}

func verifyNodeOperationRequest(wire []byte, cell string, epoch uint64, policy signerPolicy, now time.Time) (protocol.Envelope, nodeOpRequest, error) {
	var envelope protocol.Envelope
	var request nodeOpRequest
	if err := protocol.DecodeStrict(wire, &envelope, maxRegistrationWireBytes); err != nil {
		return envelope, request, err
	}
	if policy.signers == nil || policy.codec.Lookup == nil {
		return envelope, request, errors.New("node operation requires a current signer policy")
	}
	trusted, ok := policy.trusted(envelope.KeyID)
	if !ok || trusted.Actor != envelope.Actor {
		return envelope, request, errors.New("node operation signer is not in the current signed policy")
	}
	grant, ok := policy.grant(trusted.Actor)
	if !ok || !grant.CanRegisterHosts || epoch == 0 {
		return envelope, request, errors.New("node operation lacks current host-management authority")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{Region: cell, Kind: nodeOpSubmitKind,
		Actor: trusted.Actor, OperationID: envelope.OperationID, Generation: 1, Epoch: epoch}, trusted.PublicKey, now,
		protocol.VerifyPolicy{MaxLifetime: time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return envelope, request, err
	}
	if err := protocol.DecodeStrict(envelope.Payload, &request, maxRegistrationBytes); err != nil {
		return envelope, request, err
	}
	if !now.Before(envelope.ExpiresAt) {
		return envelope, request, protocol.ErrExpired
	}
	deadline, err := nodeOperationExecutionDeadline(envelope, request)
	if err != nil {
		return envelope, request, err
	}
	if !now.Before(deadline) {
		return envelope, request, protocol.ErrExpired
	}
	return envelope, request, validateNodeOperationShape(request)
}

func retainNodeOperationRequest(ctx context.Context, kv jetstream.KeyValue, id string, record nodeOperationRequestRecord) (nodeOperationRequestReference, error) {
	if kv == nil || !entityid.Valid(id) || validateNodeOperationRecord(record) != nil {
		return nodeOperationRequestReference{}, errors.New("invalid original node operation journal entry")
	}
	var original protocol.Envelope
	if err := protocol.DecodeStrict(record.Wire, &original, maxRegistrationWireBytes); err != nil || original.OperationID != id {
		return nodeOperationRequestReference{}, errors.New("original node operation ID differs from its journal key")
	}
	wire, err := protocol.EncodeJSON(record)
	if err != nil {
		return nodeOperationRequestReference{}, err
	}
	// Update at revision zero does not recreate a deleted immutable key.
	revision, err := kv.Update(ctx, nodeOperationRequestKey(id), wire, 0)
	if errors.Is(err, jetstream.ErrKeyRevisionMismatch) || errors.Is(err, jetstream.ErrKeyExists) {
		entry, readErr := kv.Get(ctx, nodeOperationRequestKey(id))
		if readErr != nil {
			return nodeOperationRequestReference{}, readErr
		}
		if !bytes.Equal(entry.Value(), wire) {
			return nodeOperationRequestReference{}, errors.New("node operation ID is already bound to another signed request or policy")
		}
		revision, err = entry.Revision(), nil
	}
	if err != nil {
		return nodeOperationRequestReference{}, err
	}
	return nodeOperationRequestReference{SHA256: controllerSHA256(record.Wire), Revision: revision}, nil
}

func (o *nodeOps) retainRequest(ctx context.Context, wire []byte, envelope protocol.Envelope) (nodeOperationRequestReference, error) {
	ctx, cancel := context.WithDeadline(ctx, envelope.ExpiresAt)
	defer cancel()
	if o.js == nil || o.fence == nil || o.fence.kv == nil {
		return nodeOperationRequestReference{}, errors.New("node operation signed source journal is unavailable")
	}
	snapshot, err := readRootResourceSnapshot(ctx, o.cfg, o.js)
	if err != nil {
		return nodeOperationRequestReference{}, err
	}
	policy, err := nodeOperationPolicy(o.cfg, snapshot)
	if err != nil {
		return nodeOperationRequestReference{}, err
	}
	if _, _, err := verifyNodeOperationRequest(wire, o.cfg.NATS.Cell, envelope.Epoch, policy, time.Now().UTC()); err != nil {
		return nodeOperationRequestReference{}, err
	}
	if err := o.fence.fencer.Guard(ctx, envelope.Epoch); err != nil {
		return nodeOperationRequestReference{}, err
	}
	reference, err := retainNodeOperationRequest(ctx, o.fence.kv, envelope.OperationID,
		nodeOperationRequestRecord{Wire: bytes.Clone(wire), Policy: nodeOperationPins(snapshot)})
	if err != nil {
		return nodeOperationRequestReference{}, err
	}
	current, err := readRootResourceSnapshot(ctx, o.cfg, o.js)
	if err != nil || !snapshot.same(current) {
		return nodeOperationRequestReference{}, errors.Join(errors.New("node operation policy changed while retaining the original request"), err)
	}
	if err := o.fence.fencer.Guard(ctx, envelope.Epoch); err != nil {
		return nodeOperationRequestReference{}, err
	}
	return reference, nil
}

func nodeOperationDigestValid(digest string) bool {
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == 32 && digest == hex.EncodeToString(decoded)
}

func validateNodeOperationRecord(record nodeOperationRequestRecord) error {
	pins := record.Policy
	if len(record.Wire) == 0 || len(record.Wire) > maxRegistrationWireBytes || pins.RootRevision == 0 || pins.SpecRevision == 0 ||
		!nodeOperationDigestValid(pins.ControllerSHA256) || !nodeOperationDigestValid(pins.RootSHA256) || !nodeOperationDigestValid(pins.SpecSHA256) {
		return errors.New("node operation journal lacks the original request or authenticated policy pins")
	}
	return nil
}

// Progress and fence records can narrow the exact signed action, never choose it.
func matchNodeOperationRequest(op nodeOp, record nodeOperationRequestRecord) (protocol.Envelope, error) {
	var envelope protocol.Envelope
	if err := validateNodeOperationRecord(record); err != nil {
		return envelope, err
	}
	if !entityid.Valid(op.ID) || !nodeOperationDigestValid(op.RequestSHA256) || op.RequestRevision == 0 || controllerSHA256(record.Wire) != op.RequestSHA256 {
		return envelope, errors.New("node operation progress lost its immutable original request")
	}
	if err := protocol.DecodeStrict(record.Wire, &envelope, maxRegistrationWireBytes); err != nil {
		return envelope, err
	}
	var request nodeOpRequest
	if err := protocol.DecodeStrict(envelope.Payload, &request, maxRegistrationBytes); err != nil {
		return envelope, err
	}
	if err := validateNodeOperationShape(request); err != nil {
		return envelope, err
	}
	if _, err := nodeOperationExecutionDeadline(envelope, request); err != nil {
		return envelope, err
	}
	node, from := request.Node, ""
	if request.Op == nodeOpRename {
		node, from = request.To, request.Node
	}
	if envelope.Kind != nodeOpSubmitKind || envelope.Generation != 1 || envelope.Epoch == 0 || envelope.OperationID != op.ID || envelope.Actor != op.Actor ||
		node != op.Node || from != op.From || request.Op != op.Op || request.OCPUs != op.OCPUs || request.MemoryGB != op.MemoryGB {
		return envelope, errors.New("node operation progress differs from its original signed request")
	}
	return envelope, nil
}

func validateNodeOperationShape(request nodeOpRequest) error {
	if err := naming.Validate(request.Node); err != nil {
		return err
	}
	switch request.Op {
	case nodeOpDrain, nodeOpUndrain, nodeOpReboot, nodeOpAdd, nodeOpRetire, nodeOpRename:
		if request.OCPUs != 0 || request.MemoryGB != 0 || (request.Op == nodeOpRename) != (request.To != "") {
			return errors.New("node operation has an invalid shape or rename target")
		}
		if request.Op == nodeOpRename {
			if err := naming.Validate(request.To); err != nil || request.To == request.Node {
				return errors.New("node rename needs a distinct valid target")
			}
		}
	case nodeOpResize:
		if request.To != "" || math.IsNaN(float64(request.OCPUs)) || math.IsNaN(float64(request.MemoryGB)) || request.OCPUs <= 0 || request.OCPUs > 64 || request.MemoryGB <= 0 || request.MemoryGB > 1024 {
			return errors.New("node resize has an invalid shape or rename target")
		}
	default:
		return errors.New("unknown signed node operation")
	}
	return nil
}

func (o *nodeOps) originalRequest(ctx context.Context, op nodeOp) (protocol.Envelope, error) {
	entry, err := o.fence.kv.Get(ctx, nodeOperationRequestKey(op.ID))
	if err != nil {
		return protocol.Envelope{}, err
	}
	if entry.Revision() != op.RequestRevision {
		return protocol.Envelope{}, errors.New("original node operation journal revision changed")
	}
	var record nodeOperationRequestRecord
	if err := json.Unmarshal(entry.Value(), &record, json.RejectUnknownMembers(true)); err != nil {
		return protocol.Envelope{}, err
	}
	return matchNodeOperationRequest(op, record)
}
