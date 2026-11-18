package pullrelease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nats-io/nats.go/jetstream"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/releasegate"
	"github.com/nats-io/nats.go"
)

func RunStagingWithdrawals(ctx context.Context, region string, fabric *nats.Conn) error {
	if region != fleet.Embedded().Staging.Label {
		return nil
	}
	key, err := fleet.Embedded().Staging.Signer()
	if err != nil {
		return err
	}
	store, err := Open(ctx, fabric, region)
	if err != nil {
		return err
	}
	watcher, err := store.kv.WatchAll(ctx)
	if err != nil {
		return err
	}
	defer watcher.Stop()
	published := map[string]struct{}{}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case entry, open := <-watcher.Updates():
			if !open {
				return errors.New("staging rollout watch closed")
			}
			if entry == nil {
				continue
			}
			if entry.Key() == region {
				var status Status
				if err := json.Unmarshal(entry.Value(), &status); err != nil {
					return err
				}
				tags := append([]string(nil), status.Bad...)
				if status.Target != nil && (status.Phase == PhaseRollingBack || status.Phase == PhaseRolledBack) {
					tags = append(tags, status.Target.Tag())
				}
				for _, tag := range tags {
					record := releasegate.Withdrawal{Region: region, Tag: tag, Reason: "staging rollout rolled back or refused the release"}
					data, err := json.Marshal(record)
					if err != nil {
						return err
					}
					if _, err := store.kv.Create(ctx, "withdrawal."+tag, data); err != nil && !errors.Is(err, jetstream.ErrKeyExists) {
						return err
					}
				}
				continue
			}
			tag, pending := strings.CutPrefix(entry.Key(), "withdrawal.")
			if !pending {
				continue
			}
			if _, done := published[tag]; done {
				continue
			}
			var record releasegate.Withdrawal
			if err := json.Unmarshal(entry.Value(), &record); err != nil {
				return err
			}
			if record.Region != region || record.Tag != tag {
				return errors.New("withdrawal outbox scope differs from its key")
			}
			record.Signed = time.Now().UTC()
			if err := publishStagingRecord(ctx, tag+releasegate.WithdrawalSuffix, record, key); err != nil {
				return fmt.Errorf("publish withdrawal for %s: %w", tag, err)
			}
			published[tag] = struct{}{}

		}
	}
}
