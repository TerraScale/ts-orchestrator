//go:build linux

package execution

import (
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/moby/swarmkit/v2/api"
)

type retainedRuntimeWitness struct {
	TaskSHA256, AdmissionSHA256, EffectID string
	Pins                                  RuntimePins
	Observation                           RuntimeObservation
}

func (s *WorkerSession) persistRuntime(grant VerifiedWorkerGrant, pins RuntimePins, observation RuntimeObservation) error {
	wire, err := json.Marshal(retainedRuntimeWitness{TaskSHA256: grant.TaskSHA256(), AdmissionSHA256: grant.AdmissionSHA256(), EffectID: grant.EffectID(), Pins: pins, Observation: observation})
	if err != nil {
		return err
	}
	return s.writeRuntimeFile(grant.TaskSHA256()+".runtime.json", wire)
}

func (s *WorkerSession) writeRuntimeFile(name string, wire []byte) error {
	if s.guardRoot == "" || filepath.Base(name) != name || len(wire) > 1<<20 {
		return ErrUnsafe
	}
	if err := verifySourceDirectory(s.guardRoot, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(s.guardRoot, ".runtime-*")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	if _, err := file.Write(wire); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(path, filepath.Join(s.guardRoot, name)); err != nil {
		return err
	}
	directory, err := os.Open(s.guardRoot)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// recoverRuntime retains old effects only for withdrawal, exact stop and close.
// A restarted host session can never use its predecessor's lease for execution.
func (s *WorkerSession) recoverRuntime(ctx context.Context, task *api.Task, hash string) (*workerTaskSession, error) {
	wire, err := readProtectedRuntimeFile(filepath.Join(s.guardRoot, hash+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, 1<<20); err != nil {
		return nil, err
	}
	var response struct {
		Nonce     string         `json:"nonce"`
		Node      string         `json:"node"`
		SessionID string         `json:"session_id"`
		Epoch     uint64         `json:"epoch"`
		Operation string         `json:"operation"`
		Error     string         `json:"error,omitempty"`
		Retryable bool           `json:"retryable,omitzero"`
		Payload   jsontext.Value `json:"payload,omitempty"`
	}
	if err := protocol.DecodeStrict(envelope.Payload, &response, 512<<10); err != nil {
		return nil, err
	}
	if response.Node != s.identity.HostNode || response.Operation != "runtime-effect" || response.Error != "" || len(response.Nonce) != 32 || response.Epoch == 0 || envelope.IssuedAt.After(time.Now().Add(2*time.Second)) {
		return nil, ErrUnsafe
	}
	scope := protocol.EnvelopeScope{Region: s.identity.Cell, Kind: "host.response.runtime-effect", Actor: "controller", OperationID: entityid.Derive("host-request", response.Nonce), Epoch: response.Epoch}
	if err := protocol.VerifyEnvelope(envelope, scope, s.controller, envelope.IssuedAt, protocol.VerifyPolicy{MaxLifetime: 10 * time.Second}); err != nil {
		return nil, err
	}
	var payload WorkerGrantPayload
	if err := protocol.DecodeStrict(response.Payload, &payload, 512<<10); err != nil {
		return nil, err
	}
	if payload.Identity.Cell != s.identity.Cell || payload.Identity.HostNode != s.identity.HostNode || payload.Identity.InstanceID != s.identity.InstanceID || payload.Identity.NodeID != s.identity.NodeID || payload.Identity.RegistrationGeneration == 0 || !entityid.Valid(payload.Identity.HostSessionID) || response.SessionID != payload.Identity.HostSessionID || payload.TaskID != task.ID ||
		payload.ServiceID != task.ServiceID || payload.TaskSHA256 != hash || payload.Epoch != response.Epoch || payload.Phase != "held" || payload.StopChallenge != "" ||
		payload.Revision == 0 || payload.IssuedAt.IsZero() || !payload.Deadline.After(payload.IssuedAt) || payload.Deadline.Sub(payload.IssuedAt) > workerGrantLifetime ||
		payload.EffectID != entityid.Derive("runtime-effect", payload.Identity.HostSessionID, hash) {
		return nil, ErrUnsafe
	}
	material, err := json.Marshal(payload.Material, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	admission, err := WorkerAdmissionSHA256(payload)
	if err != nil {
		return nil, err
	}
	grant := VerifiedWorkerGrant{payload: payload, material: material, materialSHA256: fmt.Sprintf("%x", sha256.Sum256(material)), admissionSHA256: admission, envelope: envelope}
	held := &workerTaskSession{task: task.Copy(), grant: grant, closing: true}
	witnessBytes, err := readProtectedRuntimeFile(filepath.Join(s.guardRoot, hash+".runtime.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		var witness retainedRuntimeWitness
		if err := protocol.DecodeStrict(witnessBytes, &witness, 1<<20); err != nil {
			return nil, err
		}
		bound, err := TaskSHA256(witness.Pins.Task)
		if err != nil || bound != hash || witness.Pins.ContainerSpecSHA256 != hash || witness.TaskSHA256 != hash || witness.AdmissionSHA256 != admission || witness.EffectID != grant.EffectID() || witness.Observation.ContainerID != "ts-"+task.ID {
			return nil, ErrUnsafe
		}
		held.pins, held.observation = &witness.Pins, witness.Observation
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return held, nil
}

func (s *WorkerSession) stopRecovered(task *api.Task, hash string, held *workerTaskSession) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_ = s.source.WithdrawTask(ctx, task, held.grant)
	cancel()
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	_ = s.stopRuntime(ctx, task, hash)
	cancel()
	s.settleStopped(task, hash, held)
}
