package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
)

const rootRepairInterval = 30 * time.Second

const (
	rootChainBucket = "TS_TRUST_ROOTS"
	rootChainKey    = "chain"
	rootListKind    = "trust.root.list"
	rootRotateKind  = "trust.root.rotate"
)

// rootRegistry holds the cell's root chain. Genesis is the image's baked
// root set (a lab's service_trust root). The authority leader appends
// rotation statements to a replicated KV record; every controller verifies
// the record from genesis, adopts it only when it extends the chain it
// holds, and from then on verifies with the rotated roots.
type rootRegistry struct {
	genesis  trust.Keyring
	identity trust.ChainIdentity
	// path keeps the adopted chain for restarts and the pre-NATS bootstrap
	// paths (bootstrapstart.RootChainFile); a lab keeps none.
	path string
	kv   jetstream.KeyValue
	// fencer lets the authority leader rewrite a rejected record with the
	// adopted chain, so a controller without a persisted chain never adopts
	// a rolled-back one.
	fencer authority.Fencer
	// keeps refuses a rotation whose new roots would not verify stored
	// desired state: controllers re-verify those records with the current
	// roots only, so a replaced root cannot write them.
	keeps func(context.Context, trust.Keyring) error

	// changed signals every switch of roots, coalesced, so stored desired
	// state refused under the previous roots is verified again by its owner.
	changed chan struct{}
	// repairPending stays set from a rejected record until a repair succeeds
	// or a valid record arrives; repairing runs one repair at a time off the
	// watch loop, and Run retries a pending repair every rootRepairInterval
	// (a controller that becomes leader gets no watch event).
	repairPending atomic.Bool
	repairing     atomic.Bool
	repairs       sync.WaitGroup
	// adopting orders root writes/adoption with function intent admission;
	// readers under mu never wait on I/O.
	adopting sync.Mutex
	// fence is the spec registry's launch fence: a root switch waits for
	// in-flight launches, which qualify their image under the current roots.
	fence    *sync.RWMutex
	mu       sync.Mutex
	chain    trust.RootChain
	verified trust.VerifiedRoots
}

type rootChainReply struct {
	Version  int             `json:"version"`
	Sequence uint64          `json:"sequence"`
	Head     string          `json:"head"`
	Roots    []string        `json:"roots"`
	Chain    trust.RootChain `json:"chain,omitzero"`
	Status   string          `json:"status,omitempty"`
	Error    string          `json:"error,omitempty"`
}

func newRootRegistry(genesis trust.Keyring, identity trust.ChainIdentity, chain trust.RootChain, path string) (*rootRegistry, error) {
	verified, err := trust.VerifyRootChain(genesis, identity, chain)
	if err != nil {
		return nil, fmt.Errorf("verify adopted root chain: %w", err)
	}
	return &rootRegistry{genesis: genesis, identity: identity, path: path, chain: chain, verified: verified,
		changed: make(chan struct{}, 1)}, nil
}

// current is the only root set with current authority; a controller
// without roots (a lab without spec_trust) has none.
func (r *rootRegistry) current() trust.Keyring {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.verified.Current
}

// historical holds genesis and every root the chain ever named, for
// documents a root signed before it was rotated away: an accepted host
// image stays allowed through a rotation of the root that delegated it.
func (r *rootRegistry) historical() trust.Keyring {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.verified.Historical
}

func (r *rootRegistry) open(ctx context.Context, js jetstream.JetStream, replicas int) error {
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: rootChainBucket, History: 4,
		MaxValueSize: trust.MaxRootChainBytes, Storage: jetstream.FileStorage, Replicas: replicas})
	if err != nil {
		return fmt.Errorf("open root chain: %w", err)
	}
	r.kv = kv
	entry, err := kv.Get(ctx, rootChainKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read root chain: %w", err)
	}
	r.load(ctx, entry)
	return nil
}

// Run adopts every chain another controller stores.
func (r *rootRegistry) Run(ctx context.Context) error {
	watcher, err := r.kv.Watch(ctx, rootChainKey)
	if err != nil {
		return fmt.Errorf("watch root chain: %w", err)
	}
	defer r.repairs.Wait()
	defer watcher.Stop()
	ticker := time.NewTicker(rootRepairInterval)
	defer ticker.Stop()
	for {
		ctx := observability.StartTrace(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case entry, ok := <-watcher.Updates():
			if !ok {
				return errors.New("root chain watch ended")
			}
			if entry != nil {
				r.load(ctx, entry)
			}
		case <-ticker.C:
			if r.repairPending.Load() {
				r.startRepair(ctx)
			}
		}
	}
}

// load adopts a stored chain. A removed, invalid, forked or shorter record
// is logged and ignored: the controller keeps its roots, and the authority
// leader rewrites the record with its adopted chain.
func (r *rootRegistry) load(ctx context.Context, entry jetstream.KeyValueEntry) {
	err := errors.New("record was removed")
	if entry.Operation() == jetstream.KeyValuePut {
		var chain trust.RootChain
		if chain, err = trust.DecodeRootChain(entry.Value()); err == nil {
			err = r.adopt(chain)
		}
	}
	if err == nil {
		r.repairPending.Store(false)
		return
	}
	slog.ErrorContext(ctx, "stored root chain rejected; keeping the adopted roots", observability.ComponentKey, "trust",
		"revision", entry.Revision(), "error", err)
	r.repairPending.Store(true)
	r.startRepair(ctx)
}

// startRepair rewrites a rejected record on the authority leader, off the
// watch loop and one repair at a time. A failed repair stays pending for the
// next tick.
func (r *rootRegistry) startRepair(ctx context.Context) {
	if r.fencer == nil || !r.fencer.Current().CanMutate() || !r.repairing.CompareAndSwap(false, true) {
		return
	}
	r.repairs.Go(func() {
		defer r.repairing.Store(false)
		for ctx.Err() == nil && r.fencer.Current().CanMutate() && r.repairPending.Swap(false) {
			repairCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := r.repair(repairCtx)
			cancel()
			if err != nil {
				r.repairPending.Store(true)
				slog.ErrorContext(repairCtx, "rewrite rejected root chain", observability.ComponentKey, "trust", "error", err)
				return
			}
		}
	})
}

// repair rewrites the record with the adopted chain. It re-reads the record
// first: a valid chain that extends the adopted one is adopted instead, and
// a failure to adopt it (a disk error, say) is returned, never answered by
// writing the older chain over it.
func (r *rootRegistry) repair(ctx context.Context) error {
	r.adopting.Lock()
	defer r.adopting.Unlock()
	r.mu.Lock()
	adopted := r.chain
	r.mu.Unlock()
	revision := uint64(0)
	entry, err := r.kv.Get(ctx, rootChainKey)
	switch {
	case err == nil:
		revision = entry.Revision()
		chain, err := trust.DecodeRootChain(entry.Value())
		if err == nil && chain.Extends(adopted) {
			if _, err := trust.VerifyRootChain(r.genesis, r.identity, chain); err == nil {
				return r.adoptLocked(chain)
			}
		}
	case !errors.Is(err, jetstream.ErrKeyNotFound):
		return err
	}
	encoded, err := trust.EncodeRootChain(adopted)
	if err != nil {
		return err
	}
	if err := r.fencer.Guard(ctx, r.fencer.Current().Epoch); err != nil {
		return err
	}
	if revision == 0 {
		_, err = r.kv.Create(ctx, rootChainKey, encoded)
	} else {
		_, err = r.kv.Update(ctx, rootChainKey, encoded, revision)
	}
	return err
}

// adopt switches to chain when it extends the adopted chain and verifies
// from genesis. It persists the chain first, so a restart never falls back
// to older roots.
func (r *rootRegistry) adopt(chain trust.RootChain) error {
	r.adopting.Lock()
	defer r.adopting.Unlock()
	return r.adoptLocked(chain)
}

func (r *rootRegistry) adoptLocked(chain trust.RootChain) error {
	r.mu.Lock()
	held := r.chain
	r.mu.Unlock()
	// The cheap prefix check runs first, so forks cost no verification.
	if !chain.Extends(held) {
		return errors.New("root chain forks or rolls back the adopted chain")
	}
	// Extends compares statements, not signatures: an equal chain must
	// verify too, or a record with stripped signatures would pass as valid.
	verified, err := trust.VerifyRootChain(r.genesis, r.identity, chain)
	if err != nil {
		return err
	}
	if len(chain.Rotations) == len(held.Rotations) {
		return nil
	}
	if r.path != "" {
		wire, err := trust.EncodeRootChain(chain)
		if err != nil {
			return err
		}
		if err := writeOwnerOnlyFile(filepath.Dir(r.path), filepath.Base(r.path), wire); err != nil {
			return fmt.Errorf("persist adopted root chain: %w", err)
		}
	}
	if r.fence != nil {
		r.fence.Lock()
		defer r.fence.Unlock()
	}
	r.mu.Lock()
	r.chain, r.verified = chain, verified
	r.mu.Unlock()
	slog.Info("root chain adopted", observability.ComponentKey, "trust", "sequence", verified.Sequence,
		"head", verified.Head, "roots", len(verified.Current))
	select {
	case r.changed <- struct{}{}:
	default:
	}
	return nil
}

func (r *rootRegistry) reply(status string) rootChainReply {
	r.mu.Lock()
	defer r.mu.Unlock()
	return rootChainReply{Version: 1, Sequence: r.verified.Sequence, Head: r.verified.Head,
		Roots: slices.Sorted(maps.Keys(r.verified.Current)), Chain: r.chain, Status: status}
}

// apply appends a signed rotation on the authority leader. A statement
// already on the chain is a no-op; otherwise it must extend the newer of
// the adopted chain and the stored record and still be current.
func (r *rootRegistry) apply(ctx context.Context, wire []byte, epoch uint64, fencer authority.Fencer) (rootChainReply, error) {
	r.adopting.Lock()
	defer r.adopting.Unlock()
	var signed trust.SignedRotation
	if err := protocol.DecodeStrict(wire, &signed, maxRegistrationBytes); err != nil {
		return rootChainReply{}, fmt.Errorf("decode root rotation: %w", err)
	}
	rotation, err := signed.Payload()
	if err != nil {
		return rootChainReply{}, err
	}
	r.mu.Lock()
	base := r.chain
	r.mu.Unlock()
	revision, stored := uint64(0), false
	entry, err := r.kv.Get(ctx, rootChainKey)
	switch {
	case err == nil:
		revision = entry.Revision()
		chain, err := trust.DecodeRootChain(entry.Value())
		if err == nil && chain.Extends(base) {
			if _, err = trust.VerifyRootChain(r.genesis, r.identity, chain); err == nil {
				base, stored = chain, true
			}
		}
		if err != nil {
			slog.ErrorContext(ctx, "stored root chain is invalid; extending the adopted chain", observability.ComponentKey, "trust",
				"revision", revision, "error", err)
		}
	case !errors.Is(err, jetstream.ErrKeyNotFound):
		return rootChainReply{}, fmt.Errorf("read root chain: %w", err)
	}
	next, status, onChain := base, "unchanged", false
	if rotation.Sequence >= 1 && rotation.Sequence <= uint64(len(base.Rotations)) {
		// A statement already on the chain must still carry valid signatures.
		prefix := trust.RootChain{Version: 1, Rotations: append(slices.Clone(base.Rotations[:rotation.Sequence-1]), signed)}
		if base.Extends(prefix) {
			if _, err := trust.VerifyRootChain(r.genesis, r.identity, prefix); err != nil {
				return rootChainReply{}, err
			}
			onChain = true
		}
	}
	if !onChain {
		if err := trust.RotationCurrent(signed, time.Now()); err != nil {
			return rootChainReply{}, fmt.Errorf("root rotation is not current: %w", err)
		}
		next, status = trust.RootChain{Version: 1, Rotations: append(slices.Clone(base.Rotations), signed)}, "applied"
		verified, err := trust.VerifyRootChain(r.genesis, r.identity, next)
		if err != nil {
			return rootChainReply{}, err
		}
		if r.keeps != nil {
			if err := r.keeps(ctx, verified.Current); err != nil {
				return rootChainReply{}, err
			}
		}
	}
	// A statement already on the chain only rewrites a lost, invalid or
	// older record.
	if !onChain || !stored {
		encoded, err := trust.EncodeRootChain(next)
		if err != nil {
			return rootChainReply{}, err
		}
		if err := fencer.Guard(ctx, epoch); err != nil {
			return rootChainReply{}, err
		}
		if revision == 0 {
			_, err = r.kv.Create(ctx, rootChainKey, encoded)
		} else {
			_, err = r.kv.Update(ctx, rootChainKey, encoded, revision)
		}
		if err != nil {
			return rootChainReply{}, fmt.Errorf("store root chain: %w", err)
		}
	}
	if err := r.adoptLocked(next); err != nil {
		return rootChainReply{}, err
	}
	if !onChain {
		slog.InfoContext(ctx, "root rotation applied", observability.ComponentKey, "trust", "sequence", rotation.Sequence, "epoch", epoch)
	}
	return r.reply(status), nil
}

// serve answers a signed operator request; the root signatures, not the
// operator, authorize a rotation.
func (r *rootRegistry) serve(ctx context.Context, wire []byte, policy signerPolicy, fencer authority.Fencer) (rootChainReply, error) {
	envelope, actor, err := verifyCellRequest(wire, policy, fencer)
	if err != nil {
		return rootChainReply{}, err
	}
	if envelope.Kind == rootListKind {
		return r.reply(""), nil
	}
	reply, err := r.apply(ctx, envelope.Payload, envelope.Epoch, fencer)
	if err == nil {
		slog.InfoContext(ctx, "root rotation request", observability.ComponentKey, "trust", "actor", actor,
			"sequence", reply.Sequence, "status", reply.Status)
	}
	return reply, err
}

func requestRootChain(ctx context.Context, cfg Config, runtime *natscell.Runtime, kind string, payload []byte,
) (rootChainReply, error) {
	data, err := requestLeader(ctx, cfg, runtime, kind, "trust-root", payload)
	if err != nil {
		return rootChainReply{}, err
	}
	var reply rootChainReply
	if err := protocol.DecodeStrict(data, &reply, 2*trust.MaxRootChainBytes); err != nil {
		return rootChainReply{}, fmt.Errorf("decode root chain reply: %w", err)
	}
	if reply.Version != 1 {
		return rootChainReply{}, errors.New("root chain reply requires version 1")
	}
	if reply.Error != "" {
		return rootChainReply{}, errors.New(reply.Error)
	}
	return reply, nil
}

// operatorTrustRoots prints the cell's current roots and, with out, writes
// the chain the next rotation extends.
func operatorTrustRoots(ctx context.Context, cfg Config, runtime *natscell.Runtime, out string, output io.Writer) error {
	reply, err := requestRootChain(ctx, cfg, runtime, rootListKind, []byte("{}"))
	if err != nil {
		return err
	}
	if out != "" {
		wire, err := trust.EncodeRootChain(reply.Chain)
		if err != nil {
			return err
		}
		file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return fmt.Errorf("write root chain: %w", err)
		}
		_, writeErr := file.Write(wire)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			_ = os.Remove(out)
			return fmt.Errorf("write root chain: %w", err)
		}
	}
	reply.Chain = trust.RootChain{}
	return printJSON(output, reply)
}

func operatorTrustRotate(ctx context.Context, cfg Config, runtime *natscell.Runtime, path string, output io.Writer) error {
	data, err := readBoundedConfigFile(path)
	if err != nil {
		return err
	}
	if len(data) > maxRegistrationBytes {
		return errors.New("signed root rotation exceeds the controller request bound")
	}
	reply, err := requestRootChain(ctx, cfg, runtime, rootRotateKind, data)
	if err != nil {
		return err
	}
	reply.Chain = trust.RootChain{}
	return printJSON(output, reply)
}
