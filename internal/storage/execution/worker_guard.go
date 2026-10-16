//go:build linux

package execution

import (
	"context"
	"crypto/ed25519"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/moby/swarmkit/v2/api"
	"golang.org/x/sys/unix"
)

// WorkerGuard pins the signed lease cache consumed by the existing shim logger.
// The descriptor carries no authority without the controller-signed cache bytes.
type WorkerGuard struct {
	CachePath           string         `json:"cache_path"`
	Identity            WorkerIdentity `json:"identity"`
	ControllerPublicKey []byte         `json:"controller_public_key"`
	TaskSHA256          string         `json:"task_sha256"`
	AdmissionSHA256     string         `json:"admission_sha256"`
	EffectID            string         `json:"effect_id"`
	Revision            uint64         `json:"revision"`
	Deadline            time.Time      `json:"deadline"`
	HostEpoch           uint64         `json:"host_epoch"`
	Epoch               uint64         `json:"epoch"`
}

func (s *Source) BindGuardRoot(root string) error {
	if s == nil || s.session == nil {
		return ErrUnsafe
	}
	return s.session.BindGuardRoot(root)
}

func (s *Source) RuntimeGuard(ctx context.Context, task *api.Task) (WorkerGuard, error) {
	if s == nil || s.session == nil {
		return WorkerGuard{}, ErrUnsafe
	}
	// Source admission remains mandatory before exposing the execution lease.
	if _, err := s.ResolveRuntime(ctx, task); err != nil {
		return WorkerGuard{}, err
	}
	return s.session.RuntimeGuard(ctx, task)
}

func (s *WorkerSession) BindGuardRoot(root string) error {
	if s == nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" || os.Geteuid() != 0 {
		return ErrUnsafe
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	if err := verifySourceDirectory(root, 0o700); err != nil {
		return err
	}
	s.mu.Lock()
	if s.guardRoot != "" || len(s.tasks) != 0 {
		s.mu.Unlock()
		return ErrUnsafe
	}
	s.guardRoot = root
	s.mu.Unlock()
	s.startRecovery()
	return nil
}

func (s *WorkerSession) RuntimeGuard(ctx context.Context, task *api.Task) (WorkerGuard, error) {
	grant, err := s.Resolve(ctx, task)
	if err != nil {
		return WorkerGuard{}, err
	}
	s.mu.Lock()
	root := s.guardRoot
	s.mu.Unlock()
	if root == "" {
		return WorkerGuard{}, ErrUnsafe
	}
	guard := WorkerGuard{CachePath: filepath.Join(root, grant.TaskSHA256()+".json"), Identity: s.identity,
		ControllerPublicKey: slices.Clone(s.controller), TaskSHA256: grant.TaskSHA256(), AdmissionSHA256: grant.AdmissionSHA256(),
		EffectID: grant.EffectID(), Epoch: grant.Epoch(), HostEpoch: grant.envelope.Epoch, Revision: grant.Revision(), Deadline: grant.Deadline()}
	if _, _, err := VerifyWorkerGuard(guard, grant.Revision(), grant.Deadline()); err != nil {
		return WorkerGuard{}, err
	}
	return guard, nil
}

// persistGrant writes only authenticated held grants, atomically, before the
// worker accepts their extended deadline. No secret bytes enter logger metadata.
func (s *WorkerSession) persistGrant(grant VerifiedWorkerGrant) error {
	if s.guardRoot == "" || grant.payload.Phase != "held" {
		return ErrUnsafe
	}
	if err := verifySourceDirectory(s.guardRoot, 0o700); err != nil {
		return err
	}
	wire, err := json.Marshal(grant.envelope)
	if err != nil {
		return err
	}
	return s.writeRuntimeFile(grant.TaskSHA256()+".json", wire)
}

// VerifyWorkerGuard rechecks the actual signed cache after the root process dies.
// Transport-envelope expiry does not shorten its separately signed inner lease;
// its signature and lifetime are verified at issuance, then the lease is checked now.
func VerifyWorkerGuard(guard WorkerGuard, lastRevision uint64, lastDeadline time.Time) (time.Time, uint64, error) {
	if !filepath.IsAbs(guard.CachePath) || filepath.Clean(guard.CachePath) != guard.CachePath ||
		filepath.Base(guard.CachePath) != guard.TaskSHA256+".json" || len(guard.ControllerPublicKey) != ed25519.PublicKeySize ||
		guard.TaskSHA256 == "" || guard.AdmissionSHA256 == "" || guard.Revision == 0 || guard.Deadline.IsZero() || guard.Epoch == 0 || guard.HostEpoch == 0 || !entityid.Valid(guard.EffectID) {
		return time.Time{}, 0, ErrUnsafe
	}
	data, err := readProtectedRuntimeFile(guard.CachePath)
	if err != nil {
		return time.Time{}, 0, err
	}
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(data, &envelope, 1<<20); err != nil {
		return time.Time{}, 0, err
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
		return time.Time{}, 0, err
	}
	if response.Node != guard.Identity.HostNode || response.SessionID != guard.Identity.HostSessionID || response.Epoch != guard.HostEpoch ||
		response.Operation != "runtime-effect" || response.Error != "" || len(response.Nonce) != 32 || envelope.IssuedAt.After(time.Now().Add(2*time.Second)) {
		return time.Time{}, 0, ErrUnsafe
	}
	scope := protocol.EnvelopeScope{Region: guard.Identity.Cell, Kind: "host.response.runtime-effect", Actor: "controller", OperationID: entityid.Derive("host-request", response.Nonce), Epoch: guard.HostEpoch}
	if err := protocol.VerifyEnvelope(envelope, scope, ed25519.PublicKey(guard.ControllerPublicKey), envelope.IssuedAt, protocol.VerifyPolicy{MaxLifetime: 10 * time.Second}); err != nil {
		return time.Time{}, 0, err
	}
	var payload WorkerGrantPayload
	if err := protocol.DecodeStrict(response.Payload, &payload, 512<<10); err != nil {
		return time.Time{}, 0, err
	}
	admission, err := WorkerAdmissionSHA256(payload)
	if err != nil {
		return time.Time{}, 0, err
	}
	if payload.Identity != guard.Identity || payload.TaskSHA256 != guard.TaskSHA256 || payload.EffectID != guard.EffectID || payload.Epoch != guard.Epoch || payload.LeaderEpoch != payload.Epoch ||
		admission != guard.AdmissionSHA256 || payload.Phase != "held" || payload.StopChallenge != "" || payload.IssuedAt.IsZero() || payload.Revision == 0 || payload.Revision < lastRevision || payload.Revision < guard.Revision || payload.Deadline.Before(guard.Deadline) ||
		payload.Deadline.Before(lastDeadline) || !payload.Deadline.After(payload.IssuedAt) || payload.Deadline.Sub(payload.IssuedAt) > workerGrantLifetime ||
		payload.IssuedAt.After(time.Now().Add(2*time.Second)) || !time.Now().Before(payload.Deadline) {
		return time.Time{}, 0, ErrUnsafe
	}
	return payload.Deadline, payload.Revision, nil
}

func readProtectedRuntimeFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnsafe
	}
	if err := verifySourceDirectory(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != 0 || info.Size() > 1<<20 {
		return nil, ErrUnsafe
	}
	return io.ReadAll(io.LimitReader(file, (1<<20)+1))
}
