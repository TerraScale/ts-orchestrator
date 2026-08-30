// Port of tools/TerraScale.Orchestrator.Tooling/WorkspaceTopologyLease.cs:
// serializes product development topologies within the same operating-system
// named-mutex namespace. It provides no cross-session, container, or host
// guarantee. The C# named mutex maps onto an exclusive flock on a lock file
// named after the mutex.
package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	workspaceTopologyNamespaceVariable = "TERRASCALE_VALIDATION_LEASE_NAMESPACE"
	workspaceTopologyDevelopmentLabOwner = "development-lab"
	workspaceTopologyRetryDelay          = 250 * time.Millisecond
)

// WorkspaceTopologyLease mirrors the C# WorkspaceTopologyLease class.
type WorkspaceTopologyLease struct {
	MutexName string

	release  chan struct{}
	released chan error
	closeOnce sync.Once
}

// AcquireWorkspaceTopologyLease mirrors WorkspaceTopologyLease.AcquireAsync.
func AcquireWorkspaceTopologyLease(ctx context.Context, owner string, timeout time.Duration) (*WorkspaceTopologyLease, error) {
	if owner == "" {
		return nil, errors.New("owner cannot be null or whitespace")
	}
	if owner != workspaceTopologyDevelopmentLabOwner {
		return nil, errors.New("The topology lease owner is not supported.")
	}
	if timeout <= 0 {
		return nil, errors.New("A finite positive timeout is required.")
	}

	mutexName, err := workspaceTopologyMutexName()
	if err != nil {
		return nil, err
	}

	acquired := make(chan *WorkspaceTopologyLease, 1)
	failed := make(chan error, 1)
	release := make(chan struct{})
	go runWorkspaceTopologyLeaseOwner(mutexName, timeout, ctx, release, acquired, failed)

	select {
	case lease := <-acquired:
		return lease, nil
	case err := <-failed:
		return nil, err
	}
}

// workspaceTopologyMutexName mirrors WorkspaceTopologyLease.GetMutexName.
func workspaceTopologyMutexName() (string, error) {
	leaseNamespace, present := os.LookupEnv(workspaceTopologyNamespaceVariable)
	if !present {
		leaseNamespace = envUserName()
	}
	if leaseNamespace == "" || len(leaseNamespace) > 64 || !isNamespaceToken(leaseNamespace) {
		return "", errors.New("The workspace topology lease namespace is invalid.")
	}
	return "terrascale-workspace-topology-" + leaseNamespace, nil
}

func isNamespaceToken(value string) bool {
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '.' || character == '_' || character == '-':
		default:
			return false
		}
	}
	return true
}

func runWorkspaceTopologyLeaseOwner(
	mutexName string,
	timeout time.Duration,
	ctx context.Context,
	release chan struct{},
	acquired chan<- *WorkspaceTopologyLease,
	failed chan<- error,
) {
	file, err := os.OpenFile(workspaceTopologyLockPath(mutexName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		failed <- err
		return
	}
	defer file.Close()

	deadline := time.Now().Add(timeout)
	for {
		if ctx.Err() != nil {
			failed <- ctx.Err()
			return
		}
		if remaining := time.Until(deadline); remaining <= 0 {
			failed <- errors.New("Timed out acquiring the workspace topology lease.")
			return
		}
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			break
		}
		delay := workspaceTopologyRetryDelay
		if remaining := time.Until(deadline); remaining < delay {
			delay = remaining
		}
		select {
		case <-ctx.Done():
			failed <- ctx.Err()
			return
		case <-time.After(delay):
		}
	}

	lease := &WorkspaceTopologyLease{
		MutexName: mutexName,
		release:   release,
		released:  make(chan error, 1),
	}
	acquired <- lease
	<-release
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	lease.released <- unlockErr
}

func workspaceTopologyLockPath(mutexName string) string {
	return filepath.Join(os.TempDir(), mutexName+".lock")
}

// Close mirrors WorkspaceTopologyLease.DisposeAsync: signal the owner thread,
// then wait until the mutex has actually been released.
func (lease *WorkspaceTopologyLease) Close() error {
	var err error
	lease.closeOnce.Do(func() {
		close(lease.release)
		err = <-lease.released
	})
	return err
}
