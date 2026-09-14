// Port of src/TerraScale.Orchestrator/Messaging/GlobalCellDirectoryLifecycle.cs.
package control

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

// GlobalCellDirectoryLifecycleInitialRetryDelay mirrors the C# constant.
const GlobalCellDirectoryLifecycleInitialRetryDelay = 250 * time.Millisecond

// GlobalCellDirectoryLifecycleMaximumRetryDelay mirrors the C# constant.
const GlobalCellDirectoryLifecycleMaximumRetryDelay = 5 * time.Second

// IGlobalCellDirectoryRuntimeInstance mirrors the C# interface.
type IGlobalCellDirectoryRuntimeInstance interface {
	Snapshot() GlobalCellDirectorySnapshot
	Completion() <-chan struct{}
	Dispose() error
}

// IGlobalCellDirectoryServiceRuntimeInstance mirrors the C# interface.
type IGlobalCellDirectoryServiceRuntimeInstance interface {
	Dispose()
}

// GlobalCellDirectoryLifecycle mirrors the C# class: supervises the optional
// global directory without making regional startup depend on its
// availability. A running instance is replaced after an unexpected
// completion, while the last failure remains observable.
type GlobalCellDirectoryLifecycle struct {
	startDirectory func(context.Context) (IGlobalCellDirectoryRuntimeInstance, error)
	startService   func(context.Context, IGlobalCellDirectoryRuntimeInstance) (IGlobalCellDirectoryServiceRuntimeInstance, error)
	retryDelay     func(int) time.Duration
	delay          func(context.Context, time.Duration) error
	observeFailure func(error)

	stoppingCtx context.Context
	stopping    context.CancelFunc
	supervision chan struct{}

	activeMu        sync.Mutex
	activeDirectory atomic.Pointer[valueGlobalCellDirectoryRuntimeBox]
	lastFailure     atomic.Pointer[errorBox]
	disposed        int32
}

type valueGlobalCellDirectoryRuntimeBox struct {
	instance IGlobalCellDirectoryRuntimeInstance
}

type errorBox struct{ err error }

// GlobalCellDirectoryLifecycleStart mirrors the C# Start.
func GlobalCellDirectoryLifecycleStart(
	directoryConfiguration *GlobalDirectoryNatsConfiguration,
	serviceConfiguration *GlobalDirectoryServiceNatsConfiguration,
	membership func() RegionalRuntimeMembershipSnapshot,
	authority func() RegionalAuthoritySnapshot,
	publishEnabled bool,
	cancellationToken context.Context,
	observeFailure func(error),
) (*GlobalCellDirectoryLifecycle, error) {
	if directoryConfiguration == nil {
		return nil, errors.New("(Parameter 'directoryConfiguration')")
	}

	if membership == nil {
		return nil, errors.New("(Parameter 'membership')")
	}

	if authority == nil {
		return nil, errors.New("(Parameter 'authority')")
	}

	return GlobalCellDirectoryLifecycleStartForTesting(
		func(ctx context.Context) (IGlobalCellDirectoryRuntimeInstance, error) {
			runtime, err := GlobalCellDirectoryRuntimeStartAsync(
				ctx, directoryConfiguration, membership, authority, publishEnabled)
			if err != nil {
				return nil, err
			}

			return runtime, nil
		},
		func(ctx context.Context, runtime IGlobalCellDirectoryRuntimeInstance) (IGlobalCellDirectoryServiceRuntimeInstance, error) {
			if serviceConfiguration == nil {
				return nil, nil
			}

			service, err := GlobalCellDirectoryServiceRuntimeStartAsync(
				ctx, serviceConfiguration, func() GlobalCellDirectorySnapshot { return runtime.Snapshot() })
			if err != nil {
				return nil, err
			}

			return service, nil
		},
		globalCellDirectoryLifecycleRetryDelay,
		globalCellDirectoryLifecycleDelay,
		cancellationToken,
		observeFailure)
}

// GlobalCellDirectoryLifecycleStartForTesting mirrors the C# StartForTesting.
func GlobalCellDirectoryLifecycleStartForTesting(
	startDirectory func(context.Context) (IGlobalCellDirectoryRuntimeInstance, error),
	startService func(context.Context, IGlobalCellDirectoryRuntimeInstance) (IGlobalCellDirectoryServiceRuntimeInstance, error),
	retryDelay func(int) time.Duration,
	delay func(context.Context, time.Duration) error,
	cancellationToken context.Context,
	observeFailure func(error),
) (*GlobalCellDirectoryLifecycle, error) {
	if cancellationToken == nil {
		return nil, errors.New("(Parameter 'cancellationToken')")
	}
	if startDirectory == nil {
		return nil, errors.New("(Parameter 'startDirectory')")
	}

	if retryDelay == nil {
		return nil, errors.New("(Parameter 'retryDelay')")
	}

	if delay == nil {
		return nil, errors.New("(Parameter 'delay')")
	}

	stoppingCtx, stopping := context.WithCancel(cancellationToken)
	lifecycle := &GlobalCellDirectoryLifecycle{
		startDirectory: startDirectory,
		startService:   startService,
		retryDelay:     retryDelay,
		delay:          delay,
		observeFailure: observeFailure,
		stoppingCtx:    stoppingCtx,
		stopping:       stopping,
		supervision:    make(chan struct{}),
	}

	go lifecycle.supervise()

	return lifecycle, nil
}

// Completion mirrors the C# Completion.
func (l *GlobalCellDirectoryLifecycle) Completion() <-chan struct{} {
	if l == nil {
		return nil
	}
	return l.supervision
}

// Snapshot mirrors the C# Snapshot: the active directory projection or the
// unavailable snapshot.
func (l *GlobalCellDirectoryLifecycle) Snapshot() GlobalCellDirectorySnapshot {
	if l == nil {
		return globalCellDirectoryLifecycleUnavailableSnapshot()
	}
	if active := l.activeDirectory.Load(); active != nil {
		return active.instance.Snapshot()
	}

	return globalCellDirectoryLifecycleUnavailableSnapshot()
}

// Health mirrors the C# Health.
func (l *GlobalCellDirectoryLifecycle) Health() GlobalCellDirectoryCondition {
	return l.Snapshot().Condition
}

// LastFailure mirrors the C# LastFailure.
func (l *GlobalCellDirectoryLifecycle) LastFailure() error {
	if l == nil {
		return nil
	}
	if boxed := l.lastFailure.Load(); boxed != nil {
		return boxed.err
	}

	return nil
}

// Dispose mirrors the C# DisposeAsync.
func (l *GlobalCellDirectoryLifecycle) Dispose() {
	if l == nil {
		return
	}
	if !atomic.CompareAndSwapInt32(&l.disposed, 0, 1) {
		return
	}

	if l.stopping != nil {
		l.stopping()
	}
	if l.supervision != nil {
		<-l.supervision
	}
}

func (l *GlobalCellDirectoryLifecycle) supervise() {
	defer close(l.supervision)

	for attempt := 1; ; attempt++ {
		var directory IGlobalCellDirectoryRuntimeInstance
		var service IGlobalCellDirectoryServiceRuntimeInstance
		var failure error

		func() {
			defer func() {
				l.activeDirectory.Store(nil)
				globalCellDirectoryLifecycleDisposeInstances(service, directory)
			}()

			started, err := l.startDirectory(l.stoppingCtx)
			if err != nil {
				failure = err
				return
			}

			if started == nil {
				failure = errors.New("(Parameter 'directory')")
				return
			}

			directory = started
			if l.startService != nil {
				startedService, err := l.startService(l.stoppingCtx, directory)
				if err != nil {
					failure = err
					return
				}

				service = startedService
			}

			l.activeDirectory.Store(&valueGlobalCellDirectoryRuntimeBox{instance: directory})
			select {
			case <-directory.Completion():
				failure = errors.New("The global cell directory runtime stopped unexpectedly.")
			case <-l.stoppingCtx.Done():
				failure = context.Canceled
			}
		}()

		if l.stoppingCtx.Err() != nil {
			return
		}

		if failure == nil {
			continue
		}

		l.lastFailure.Store(&errorBox{err: failure})
		if l.observeFailure != nil {
			l.observeFailure(failure)
		}

		if err := l.delay(l.stoppingCtx, l.retryDelay(attempt)); err != nil {
			return
		}
	}
}

func globalCellDirectoryLifecycleDisposeInstances(
	service IGlobalCellDirectoryServiceRuntimeInstance,
	directory IGlobalCellDirectoryRuntimeInstance,
) {
	// Disposal failures must not terminate regional control or stop a
	// transient global-directory retry. The failed instance is no longer
	// published through Snapshot, and the original start/completion error
	// remains the primary LastFailure signal.
	if service != nil {
		service.Dispose()
	}

	if directory != nil {
		_ = directory.Dispose()
	}
}

func globalCellDirectoryLifecycleRetryDelay(attempt int) time.Duration {
	exponent := attempt - 1
	if exponent > 4 {
		exponent = 4
	}

	milliseconds := float64(GlobalCellDirectoryLifecycleInitialRetryDelay/time.Millisecond) *
		float64(int64(1)<<uint(exponent))

	maximum := float64(GlobalCellDirectoryLifecycleMaximumRetryDelay / time.Millisecond)
	if milliseconds > maximum {
		milliseconds = maximum
	}

	return time.Duration(milliseconds) * time.Millisecond
}

func globalCellDirectoryLifecycleDelay(ctx context.Context, duration time.Duration) error {
	if ctx == nil {
		return errors.New("(Parameter 'ctx')")
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func globalCellDirectoryLifecycleUnavailableSnapshot() GlobalCellDirectorySnapshot {
	return GlobalCellDirectorySnapshot{
		SchemaVersion: protocol.ProtocolVersion.Current(),
		ObservedAt:    time.Now().UTC(),
		ActiveCells:   0,
		StaleCells:    0,
		Condition:     GlobalCellDirectoryConditionUnavailable,
		Cells:         []GlobalCellDirectoryEntry{},
	}
}
