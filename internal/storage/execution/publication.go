//go:build linux

package execution

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/moby/swarmkit/v2/api"
)

type publication struct {
	path     string
	file     os.FileInfo
	listener *net.UnixListener
	cancel   context.CancelFunc
	done     chan struct{}
}

func (s *Source) ensurePublication(ctx context.Context, task *api.Task, entry *sourceEntry, plan *host.ContainerMember) error {
	s.mu.Lock()
	current, revoked := entry.publication, entry.revoked
	s.mu.Unlock()
	if revoked {
		return ErrUnsafe
	}
	if current != nil {
		select {
		case <-current.done:
			return ErrUnsafe
		default:
		}
		file, err := os.Lstat(current.path)
		if err != nil || !os.SameFile(current.file, file) {
			return errors.Join(ErrUnsafe, err)
		}
		return nil
	}
	client, err := nativerootoci.NewInstancePrincipalClient(ctx, plan.Publication.Region)
	if err != nil {
		return err
	}
	service, err := nativerootoci.NewService(plan.Publication, client)
	if err != nil {
		return err
	}
	listener, file, err := host.ListenContainerPublication(plan.PublicationSocket, host.WorkloadIdentity{UID: entry.material.Mount.UID, GID: entry.material.Mount.GID})
	if err != nil {
		return err
	}
	// The signed task session owns this listener across individual executor calls.
	// Its independent expiry watchdog closes it before attempting writer stop.
	lifetime, cancel := context.WithCancel(context.Background())
	created := &publication{path: plan.PublicationSocket, file: file, listener: listener, cancel: cancel, done: make(chan struct{})}
	s.mu.Lock()
	if entry.revoked || entry.publication != nil {
		s.mu.Unlock()
		cancel()
		listener.Close()
		host.RemoveContainerPublicationSocket(created.path, created.file)
		return ErrUnsafe
	}
	entry.publication = created
	s.mu.Unlock()
	go func() {
		defer close(created.done)
		_ = nativerootoci.Serve(lifetime, listener, service, func(ctx context.Context, peer nativerootoci.Peer) (time.Time, error) {
			return s.authorizePublication(ctx, task, entry, created, peer)
		})
	}()
	return nil
}

func (s *Source) authorizePublication(ctx context.Context, task *api.Task, entry *sourceEntry, listener *publication, peer nativerootoci.Peer) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil {
		return time.Time{}, ErrUnsafe
	}
	s.mu.Lock()
	pins, revoked, active := entry.pins, entry.revoked, entry.publication == listener
	s.mu.Unlock()
	if pins == nil || revoked || !active || peer.PID < 2 || peer.UID != entry.material.Mount.UID || peer.GID != entry.material.Mount.GID {
		return time.Time{}, ErrUnsafe
	}
	file, err := os.Lstat(listener.path)
	if err != nil || !os.SameFile(listener.file, file) {
		return time.Time{}, ErrUnsafe
	}
	grant, err := s.session.Resolve(ctx, task)
	if err != nil || grant.AdmissionSHA256() != entry.grant.AdmissionSHA256() {
		return time.Time{}, errors.Join(ErrUnsafe, err)
	}
	// A pinned old desired cannot gain authority merely because its session renewed.
	if _, err := s.admit(ctx, task); err != nil {
		return time.Time{}, err
	}
	actual, err := s.runtime.Observe(ctx, *pins)
	if err != nil || actual.State != containerd.Running || actual.Process.PID != peer.PID || actual.Process.UID != peer.UID || actual.Process.GID != peer.GID {
		return time.Time{}, errors.Join(ErrUnsafe, err)
	}
	if err := s.session.VerifyCurrent(ctx, task, grant); err != nil {
		return time.Time{}, err
	}
	s.mu.Lock()
	revoked = entry.revoked || entry.publication != listener
	s.mu.Unlock()
	if revoked {
		return time.Time{}, ErrUnsafe
	}
	// Cancellation precedes the manager's grant deadline, leaving time to stop.
	return grant.Deadline().Add(-workerStopReserve), nil
}

// WithdrawTask works from retained sealed identity after lease expiry. It cannot
// reacquire authority or wait for network I/O before revoking publication.
func (s *Source) WithdrawTask(ctx context.Context, task *api.Task, grant VerifiedWorkerGrant) error {
	if s == nil || task == nil || ctx == nil {
		return ErrUnsafe
	}
	hash, err := TaskSHA256(task)
	if err != nil || grant.TaskSHA256() != hash || grant.AdmissionSHA256() == "" {
		return ErrUnsafe
	}
	s.mu.Lock()
	entry := s.entries[hash]
	if entry == nil {
		s.mu.Unlock()
		return nil
	}
	if entry.grant.AdmissionSHA256() != grant.AdmissionSHA256() {
		s.mu.Unlock()
		return ErrUnsafe
	}
	entry.revoked = true
	current := entry.publication
	entry.publication = nil
	s.mu.Unlock()
	if current == nil {
		return nil
	}
	current.cancel()
	closeErr := current.listener.Close()
	if errors.Is(closeErr, net.ErrClosed) {
		closeErr = nil
	}
	removeErr := host.RemoveContainerPublicationSocket(current.path, current.file)
	return errors.Join(closeErr, removeErr)
}
