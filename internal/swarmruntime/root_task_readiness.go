//go:build linux

package swarmruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionleader"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/moby/swarmkit/v2/api"
)

// RootTaskReadiness owns independent read sources. The ordinary manager relays
// original signed observations; it supplies no readiness authority to root.
type RootTaskReadiness struct {
	control   api.ControlReader
	mutations *authority.Reader
	lease     *authority.LeaseAdmission
	producer  *executionleader.ReadOnlyVerifier
	hosts     *host.Reader
	relay     *host.Agent
}

func NewRootTaskReadiness(control api.ControlReader, mutations *authority.Reader, lease *authority.LeaseAdmission, producer *executionleader.ReadOnlyVerifier, hosts *host.Reader, relay *host.Agent) (*RootTaskReadiness, error) {
	if control == nil || mutations == nil || lease == nil || producer == nil || hosts == nil || relay == nil {
		return nil, errors.New("root task readiness requires actual independent authority and host sources")
	}
	return &RootTaskReadiness{control: control, mutations: mutations, lease: lease, producer: producer, hosts: hosts, relay: relay}, nil
}

func (s *RootTaskReadiness) CaptureTaskReadiness(ctx context.Context, task *api.Task) (*TaskReadinessWitness, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || task == nil || task.Status.State != api.TaskStateRunning {
		return nil, authority.ErrFenced
	}
	if err := s.lease.Guard(ctx); err != nil {
		return nil, err
	}
	task = task.Copy()
	hash, err := executionwire.TaskSHA256(task)
	if err != nil {
		return nil, err
	}
	effects, err := s.mutations.ListAllUnresolvedRuntimeEffects(ctx)
	if err != nil {
		return nil, err
	}
	var original *authority.RuntimeEffect
	for i := range effects {
		if effects[i].TaskID != task.ID {
			continue
		}
		if original != nil {
			return nil, errors.New("stateful task has ambiguous unresolved effects")
		}
		original = &effects[i]
	}
	if original == nil || original.Phase != authority.RuntimeEffectHeld || original.Epoch != s.lease.Epoch() ||
		original.TaskSHA256 != hash || original.ServiceID != task.ServiceID || original.NodeID != task.NodeID || !time.Now().Before(original.ExpiresAt) {
		return nil, authority.ErrFenced
	}
	material, err := runtimeMaterial(*original)
	if err != nil {
		return nil, err
	}
	source, err := s.hosts.AdmitRuntimeReadinessSource(ctx, *original)
	if err != nil {
		return nil, err
	}
	deadline := source.Deadline()
	for _, limit := range []time.Time{s.lease.Deadline(), time.Now().Add(3 * time.Second)} {
		if limit.Before(deadline) {
			deadline = limit
		}
	}
	verify := func(check context.Context) error {
		if err := s.lease.Guard(check); err != nil {
			return err
		}
		if err := source.Guard(check); err != nil {
			return err
		}
		actual, err := currentControlTask(check, s.control, source.Caller().Registration(), task, hash)
		if err != nil {
			return err
		}
		if actual.Status.State != api.TaskStateRunning {
			return authority.ErrFenced
		}
		history, err := s.mutations.ListRuntimeEffectHistory(check, original.Scope)
		if err != nil {
			return err
		}
		found := false
		for _, current := range history {
			if current.EffectID != original.EffectID {
				continue
			}
			if !sameReadinessEffect(*original, current) {
				return authority.ErrFenced
			}
			found = true
		}
		if !found {
			return authority.ErrFenced
		}
		if err := s.producer.VerifyCurrent(check, actual, source.Caller(), material); err != nil {
			return err
		}
		if err := source.Guard(check); err != nil {
			return err
		}
		return s.lease.Guard(check)
	}
	probe := func(check context.Context) (host.ManagedRuntimeReport, error) {
		check, cancel := context.WithDeadline(check, deadline)
		defer cancel()
		if err := verify(check); err != nil {
			return host.ManagedRuntimeReport{}, err
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return host.ManagedRuntimeReport{}, err
		}
		challenge := host.ContainerReadinessChallenge{Nonce: hex.EncodeToString(nonce[:]), TaskID: original.TaskID, TaskSHA256: original.TaskSHA256, AdmissionSHA256: original.AdmissionSHA256, EffectID: original.EffectID, Deadline: deadline}
		envelope, err := s.relay.ObserveContainerReadiness(check, challenge)
		if err != nil {
			return host.ManagedRuntimeReport{}, err
		}
		report, err := source.Verify(check, challenge, envelope)
		if err != nil {
			return host.ManagedRuntimeReport{}, err
		}
		if report.Container == nil || report.ServingProof == nil {
			return host.ManagedRuntimeReport{}, memberstatus.ErrNotServing
		}
		expected := memberstatus.Identity{Process: memberstatus.Process{PID: report.Container.MemberPID, StartNonce: report.ProcessBootID}, Scope: material.Scope, Authority: material.MemberAuthority}
		if err := memberstatus.VerifyReportedServing(*report.ServingProof, expected, material.Survivor); err != nil {
			return host.ManagedRuntimeReport{}, err
		}
		if err := verify(check); err != nil {
			return host.ManagedRuntimeReport{}, err
		}
		if !time.Now().Before(deadline) {
			return host.ManagedRuntimeReport{}, authority.ErrFenced
		}
		return report, nil
	}
	report, err := probe(ctx)
	if err != nil {
		return nil, err
	}
	binding, boot, generation := *report.Container, report.ProcessBootID, report.ClientCredentialGeneration
	return &TaskReadinessWitness{deadline: deadline, recheck: func(check context.Context) error {
		current, err := probe(check)
		if err != nil {
			return err
		}
		if *current.Container != binding || current.ProcessBootID != boot || current.ClientCredentialGeneration != generation {
			return memberstatus.ErrStaleBinding
		}
		return nil
	}}, nil
}
