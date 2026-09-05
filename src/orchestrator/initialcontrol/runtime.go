package initialcontrol

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

// Runtime owns only initial authority and membership. Delivery, command
// ingress, journal writers and estate workers are deliberately not composed.
type Runtime struct {
	broker                       *bootstrap.NatsServer
	regionalClient, globalClient *nats.Conn
	regional, global             *authority.RegionalAuthorityCoordinator
	membership                   *directory.RegionalRuntimeMembership
	identity                     *directory.RegionalRuntimeMembershipIdentity
	cancel                       context.CancelFunc
	brokerCancel                 context.CancelFunc
	done                         chan struct{}
	once                         sync.Once
	mu                           sync.Mutex
	err                          error
	closeErr                     error
	closing                      bool
	capture                      *preliminaryWorker
}

func Start(ctx context.Context, admission *initialgrant.Admission) (result *Runtime, resultErr error) {
	if ctx == nil || admission == nil {
		return nil, errors.New("initial control: trusted launch admission is required")
	}
	if err := admission.Check(ctx); err != nil {
		return nil, err
	}
	if err := admission.VerifyMaterial(); err != nil {
		return nil, err
	}
	cfg := admission.Config()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	digest, err := ProfileDigest(cfg.Cell, cfg.SeedInstance)
	if err != nil {
		return nil, err
	}
	if digest != cfg.ProfileSHA256 {
		return nil, errors.New("initial control: retained profile digest differs from signed configuration")
	}
	required, err := RequiredStorageBytes(cfg.Cell, cfg.SeedInstance)
	if err != nil {
		return nil, err
	}
	if cfg.Broker.StorageBudgetBytes < required {
		return nil, errors.New("initial control: admitted storage budget cannot retain the complete profiles and overhead")
	}
	profiles, err := buildProfiles(cfg.Cell, cfg.SeedInstance)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithDeadline(ctx, admission.ExpiresAt())
	r := &Runtime{cancel: cancel, done: make(chan struct{})}
	started := false
	defer func() {
		if !started {
			resultErr = errors.Join(resultErr, r.Close())
		}
	}()
	guard := func(parent context.Context, fn func(context.Context) error) error {
		if err := lifetime.Err(); err != nil {
			return err
		}
		bounded, stop := context.WithTimeout(parent, 5*time.Second)
		defer stop()
		// Coordinator and membership loops own background contexts. Merge the
		// admitted runtime lifetime so expiry/cancellation also cancels their I/O.
		stopLifetime := context.AfterFunc(lifetime, stop)
		defer stopLifetime()
		return admission.WithinMutation(bounded, func(op context.Context) error {
			if err := lifetime.Err(); err != nil {
				return err
			}
			return fn(op)
		})
	}
	if cfg.Role == "seed" {
		if err = validateBrokerJSON(cfg.Broker.Configuration); err != nil {
			return nil, err
		}
		tlsConfig, tlsErr := loadTLS(cfg.Broker.TLS)
		if tlsErr != nil {
			return nil, tlsErr
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		brokerConfig, err := brokerConfigurationWithoutTLS(cfg)
		if err != nil {
			return nil, err
		}
		startup, startupCancel := context.WithTimeout(lifetime, 30*time.Second)
		err = admission.WithinMutation(startup, func(operation context.Context) error {
			if err := checkDiskBudget(cfg.Broker.StoreDir, cfg.Broker.StorageBudgetBytes); err != nil {
				return err
			}
			var e error
			// Broker shutdown is supervised below, after workers and clients stop.
			// It must not race those workers merely because their lifetime expired.
			brokerLifetime, brokerCancel := context.WithCancel(context.Background())
			r.brokerCancel = brokerCancel
			stopStartup := context.AfterFunc(operation, brokerCancel)
			defer stopStartup()
			r.broker, e = bootstrap.StartNatsServerConfiguration(brokerLifetime, brokerConfig, 5*time.Second, tlsConfig, validateBrokerOptions(cfg, tlsConfig))
			if e == nil {
				e = operation.Err()
			}
			return e
		})
		startupCancel()
		if err != nil {
			return nil, err
		}
		for _, scope := range []struct {
			store    initialgrant.Store
			profile  accountProfile
			regional bool
		}{{cfg.Regional, profiles.Regional, true}, {*cfg.Global, profiles.Global, false}} {
			operation, stop := context.WithTimeout(lifetime, 30*time.Second)
			err = admission.WithinMutation(operation, func(op context.Context) error {
				nc, e := connect(op, cfg.Broker, *scope.store.Provisioner)
				if e != nil {
					return e
				}
				defer nc.Close()
				js, e := jetstream.New(nc)
				if e != nil {
					return e
				}
				return provision(op, js, scope.profile, scope.regional, cfg.Cell, cfg.SeedInstance)
			})
			stop()
			if err != nil {
				return nil, err
			}
		}
	}
	operation, stop := context.WithTimeout(lifetime, 15*time.Second)
	defer stop()
	r.regionalClient, err = connect(operation, cfg.Broker, cfg.Regional.Runtime)
	if err != nil {
		return nil, err
	}
	regionalJS, err := jetstream.New(r.regionalClient)
	if err != nil {
		return nil, err
	}
	if err = readback(operation, regionalJS, profiles.Regional, false); err != nil {
		return nil, err
	}
	leaders, err := regionalJS.KeyValue(operation, "ORCH_LEADERS")
	if err != nil {
		return nil, err
	}
	r.regional, err = authority.RegionalAuthorityCoordinatorStartAsyncGuarded(operation, leaders, cfg.Cell, cfg.Instance, guard)
	if err != nil {
		return nil, err
	}
	if cfg.Role == "seed" {
		r.globalClient, err = connect(operation, cfg.Broker, cfg.Global.Runtime)
		if err != nil {
			return nil, err
		}
		globalJS, e := jetstream.New(r.globalClient)
		if e != nil {
			return nil, e
		}
		if e = readback(operation, globalJS, profiles.Global, false); e != nil {
			return nil, e
		}
		globalLeaders, e := globalJS.KeyValue(operation, "ORCH_LEADERS")
		if e != nil {
			return nil, e
		}
		r.global, err = authority.RegionalAuthorityCoordinatorStartGlobalAsyncGuarded(operation, globalLeaders, cfg.Cell, cfg.Instance, guard)
		if err != nil {
			return nil, err
		}
	}
	signerBytes, err := readCredential(cfg.Membership.SigningKeyFile, "", true)
	if err != nil {
		return nil, err
	}
	r.identity, err = directory.RegionalRuntimeMembershipIdentityFromPEM(signerBytes)
	clear(signerBytes)
	if err != nil {
		return nil, err
	}
	if r.identity.PublicKey != cfg.Membership.PublicKey {
		return nil, errors.New("initial control: membership signer differs from owner pin")
	}
	pinsData, err := readCredential(cfg.Membership.PinsFile, cfg.Membership.PinsSHA256, false)
	if err != nil {
		return nil, err
	}
	pins := map[string]string{}
	if err = json.Unmarshal(pinsData, &pins); err != nil {
		return nil, err
	}
	if len(pins) != len(cfg.Peers) {
		return nil, errors.New("initial control: membership pin inventory differs from admitted peers")
	}
	for _, peer := range cfg.Peers {
		if pins[peer.Instance] != peer.MembershipPublicKey {
			return nil, errors.New("initial control: membership peer pin differs from signed configuration")
		}
	}
	store, err := regionalJS.KeyValue(operation, "ORCH_RUNTIME")
	if err != nil {
		return nil, err
	}
	protected := guardedKV{KeyValue: store, guard: guard}
	r.membership, err = directory.RegionalRuntimeMembershipStartAsync(operation, protected, messaging.NewNatsTopology(cfg.Cell, 1, cfg.Instance), "initial-gru-r1", []string{"authority", "initial-gru-r1", "regional-membership"}, time.Now().UTC(), r.regional.Snapshot, r.identity, pins)
	if err != nil {
		return nil, err
	}
	if cfg.PreliminaryCapture != nil {
		r.capture = startPreliminaryWorker(lifetime, admission, r.GlobalAuthority)
	}
	started = true
	go r.supervise(lifetime, admission)
	return r, nil
}

func (r *Runtime) supervise(ctx context.Context, a *initialgrant.Admission) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var global, broker <-chan struct{}
	if r.global != nil {
		global = r.global.Completion()
	}
	if r.broker != nil {
		broker = r.broker.Completion()
	}
	for {
		var terminal error
		select {
		case <-r.done:
			return
		case <-ctx.Done():
			terminal = ctx.Err()
			if errors.Is(terminal, context.Canceled) {
				terminal = nil
			}
		case <-r.regional.Completion():
			terminal = errors.New("initial control: regional authority stopped")
		case <-global:
			terminal = errors.New("initial control: global authority stopped")
		case <-r.membership.Completion():
			terminal = errors.New("initial control: membership stopped")
		case <-broker:
			terminal = errors.New("initial control: embedded broker stopped")
		case <-ticker.C:
			if r.regionalClient.IsClosed() || r.globalClient != nil && r.globalClient.IsClosed() {
				terminal = errors.New("initial control: authenticated broker connection closed")
				break
			}
			bounded, cancel := context.WithTimeout(ctx, time.Second)
			terminal = a.Check(bounded)
			cancel()
			if terminal == nil {
				continue
			}
		}
		r.mu.Lock()
		if r.closing {
			r.mu.Unlock()
			return
		}
		r.err = terminal
		r.mu.Unlock()
		_ = r.Close()
		return
	}
}
func (r *Runtime) Completion() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.done
}
func (r *Runtime) Err() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return errors.Join(r.err, r.closeErr)
}
func (r *Runtime) RegionalAuthority() authority.RegionalAuthoritySnapshot {
	if r == nil || r.regional == nil {
		return authority.RegionalAuthoritySnapshot{}
	}
	select {
	case <-r.done:
		return authority.RegionalAuthoritySnapshot{}
	default:
	}
	return r.regional.Snapshot()
}
func (r *Runtime) GlobalAuthority() authority.RegionalAuthoritySnapshot {
	if r == nil || r.global == nil {
		return authority.RegionalAuthoritySnapshot{}
	}
	select {
	case <-r.done:
		return authority.RegionalAuthoritySnapshot{}
	default:
	}
	return r.global.Snapshot()
}
func (r *Runtime) Membership() directory.RegionalRuntimeMembershipSnapshot {
	if r == nil || r.membership == nil {
		return directory.RegionalRuntimeMembershipSnapshot{}
	}
	return r.membership.Snapshot()
}
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		r.mu.Lock()
		r.closing = true
		r.mu.Unlock()
		// A normal close removes its own session under fresh admission. After
		// retirement or expiry the guarded delete refuses and the record expires.
		if r.membership != nil {
			if err := r.membership.Dispose(); err != nil && err != context.Canceled {
				r.mu.Lock()
				r.closeErr = errors.Join(r.closeErr, err)
				r.mu.Unlock()
			}
		}
		r.cancel()
		if r.capture != nil {
			<-r.capture.done
		}
		if r.global != nil {
			r.global.Dispose()
		}
		if r.regional != nil {
			r.regional.Dispose()
		}
		if r.globalClient != nil {
			r.globalClient.Close()
		}
		if r.regionalClient != nil {
			r.regionalClient.Close()
		}
		if r.identity != nil {
			r.identity.Dispose()
		}
		if r.broker != nil {
			if err := r.broker.Close(); err != nil {
				r.mu.Lock()
				r.closeErr = errors.Join(r.closeErr, err)
				r.mu.Unlock()
			}
		}
		if r.brokerCancel != nil {
			r.brokerCancel()
		}
		close(r.done)
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closeErr
}

func checkDiskBudget(path string, budget int64) error {
	// Require an explicit free-space margin before opening the seed broker.
	ancestor := path
	for {
		_, err := os.Stat(ancestor)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return err
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return err
		}
		ancestor = parent
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(ancestor, &stat); err != nil {
		return err
	}
	if uint64(budget) > stat.Bavail*uint64(stat.Bsize) {
		return errors.New("initial control: storage filesystem lacks the admitted budget")
	}
	return nil
}

type guardedKV struct {
	jetstream.KeyValue
	guard func(context.Context, func(context.Context) error) error
}

func (g guardedKV) Create(ctx context.Context, key string, value []byte, opts ...jetstream.KVCreateOpt) (rev uint64, err error) {
	err = g.guard(ctx, func(op context.Context) error {
		var e error
		rev, e = g.KeyValue.Create(op, key, value, opts...)
		return e
	})
	return
}
func (g guardedKV) Update(ctx context.Context, key string, value []byte, last uint64) (rev uint64, err error) {
	err = g.guard(ctx, func(op context.Context) error {
		var e error
		rev, e = g.KeyValue.Update(op, key, value, last)
		return e
	})
	return
}
func (g guardedKV) Delete(ctx context.Context, key string, opts ...jetstream.KVDeleteOpt) error {
	return g.guard(ctx, func(op context.Context) error { return g.KeyValue.Delete(op, key, opts...) })
}
