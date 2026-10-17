package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
)

// publishInitial uses only the original protected creation authority. An absent
// record, ordinary leader lease or later genesis observation cannot authorize it.
func (r *rootRegistry) publishInitial(ctx context.Context, runtime *natscell.Runtime, proof region.VerifiedBrokerCreation) error {
	if r == nil || runtime == nil || ctx == nil {
		return errors.New("initial root publication requires its original broker and source")
	}
	ctx, finish, err := proof.BoundContext(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if err := proof.RevalidateRuntime(ctx, runtime); err != nil {
		return err
	}
	if !strings.EqualFold(proof.Info().Cell, r.identity.Cell) {
		return errors.New("initial root publication names another cell")
	}
	wire, err := proof.InitialRootChain(ctx)
	if err != nil {
		return err
	}
	chain, err := trust.DecodeRootChain(wire)
	if err != nil {
		return err
	}
	if _, err := trust.VerifyRootChain(r.genesis, r.identity, chain); err != nil {
		return err
	}
	r.adopting.Lock()
	defer r.adopting.Unlock()
	r.mu.Lock()
	held, err := trust.EncodeRootChain(r.chain)
	r.mu.Unlock()
	if err != nil || !bytes.Equal(held, wire) {
		return errors.Join(errors.New("original root source differs from the adopted registry"), err)
	}
	guard := func() error {
		if err := proof.RevalidateRuntime(ctx, runtime); err != nil {
			return err
		}
		current, err := proof.InitialRootChain(ctx)
		if err != nil || !bytes.Equal(current, wire) {
			return errors.Join(errors.New("original root source changed before publication"), err)
		}
		return ctx.Err()
	}
	if err := guard(); err != nil {
		return err
	}
	// Obtain the target from the proof-bound runtime, not a caller's KV handle.
	kv, err := runtime.JetStream().KeyValue(ctx, rootChainBucket)
	if err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if err := proof.PrepareRootPublication(ctx, runtime); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if _, err := kv.Create(ctx, rootChainKey, wire); err != nil && !errors.Is(err, jetstream.ErrKeyExists) {
		return fmt.Errorf("publish initial root chain: %w", err)
	}
	if err := guard(); err != nil {
		return err
	}
	entry, err := kv.Get(ctx, rootChainKey)
	if err != nil {
		return err
	}
	if entry.Operation() != jetstream.KeyValuePut || entry.Revision() == 0 || !bytes.Equal(entry.Value(), wire) {
		return errors.New("initial root publication differs from its exact source")
	}
	if err := guard(); err != nil {
		return err
	}
	if err := proof.AdoptRootPublication(ctx, runtime); err != nil {
		return err
	}
	return guard()
}
