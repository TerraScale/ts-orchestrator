package app

import (
	"context"
	"encoding/json/v2"
	"errors"

	"github.com/nats-io/nats.go/jetstream"
)

// Unsigned holds can stop an effect. Only the retained signed action or real
// readiness supplies authority to change a backend's serving state.
func rootTrafficHolds(ctx context.Context, js jetstream.JetStream, nodes []string) (map[string]fenceRecord, func(context.Context) error, error) {
	initial := map[string]rootNodeJournalPin{}
	held := map[string]fenceRecord{}
	for _, node := range nodes {
		if !grantToken.MatchString(node) {
			return nil, nil, errors.New("task traffic hold has an invalid node")
		}
		pin, err := readRootNodeJournal(ctx, js, fencedKey(node))
		if err != nil {
			return nil, nil, err
		}
		initial[node] = pin
		if !pin.present() {
			continue
		}
		var record fenceRecord
		if len(pin.wire) > 32<<10 {
			return nil, nil, errors.New("task traffic hold exceeds its finite bound")
		}
		if err := json.Unmarshal(pin.wire, &record, json.RejectUnknownMembers(true)); err != nil {
			return nil, nil, err
		}
		if len(record.Backends) > 64 || len(record.holders()) > 4 {
			return nil, nil, errors.New("task traffic hold exceeds its finite bound")
		}
		held[node] = record
	}
	check := func(ctx context.Context) error {
		for _, node := range nodes {
			current, err := readRootNodeJournal(ctx, js, fencedKey(node))
			if err != nil {
				return err
			}
			if !initial[node].same(current) {
				return errors.New("task traffic hold changed after original admission")
			}
		}
		return ctx.Err()
	}
	return held, check, check(ctx)
}
