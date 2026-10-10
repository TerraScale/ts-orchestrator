package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/atlas"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const (
	alertBucket       = "TS_BUDGET_ALERT"
	alertKey          = "status"
	statusTokenSecret = "ts-status-operator-token"
	statusTimeout     = 10 * time.Second
	maxAlertBytes     = 4 << 10
)

// budgetAlert opens and resolves the ts-status budget warning. Only the
// allocator's tick reads or writes its fields other than js, replicas and status.
type budgetAlert struct {
	js       jetstream.JetStream
	replicas int
	status   budget.StatusPage
	kv       jetstream.KeyValue // opened on the first use
	// unsaved is a change ts-status already took but KV did not record yet.
	unsaved *alertRecord
	// missing is set while the operator token is absent, so the decision is journaled once.
	missing bool
	// failure is the last failure logged, so a repeat of it is not logged again.
	failure string
}

// alertRecord is the warning's durable state. A new leader reads it and neither reopens nor forgets the warning.
type alertRecord struct {
	Open     bool      `json:"open"`
	Incident string    `json:"incident,omitempty"`
	At       time.Time `json:"at,omitzero"`
}

func newBudgetAlert(js jetstream.JetStream, replicas int, atlasConfig func() *atlas.Config) budgetAlert {
	return budgetAlert{js: js, replicas: replicas, status: budget.StatusPage{URL: budget.StatusOperatorURL,
		Token: statusOperatorToken(atlasConfig), HTTP: &http.Client{Timeout: statusTimeout}}}
}

// statusOperatorToken reads the ts-status operator token from the Vault of the atlas publish key.
// shortcut: assumes the home's Vault is the atlas Vault, upgrade to TS-803 Vault discovery when it lands.
func statusOperatorToken(atlasConfig func() *atlas.Config) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		config := atlasConfig()
		if config == nil {
			return "", budget.ErrNoStatusToken
		}
		ref := config.PublishKey
		ref.Name = statusTokenSecret
		value, err := vaultsecret.ReadRefVersioned(ctx, ref)
		if vaultsecret.Absent(err) {
			return "", budget.ErrNoStatusToken
		}
		if err != nil {
			return "", err
		}
		return value.Value, nil
	}
}

// alertBudget opens the ts-status warning when the budget alert turns on and
// resolves it when the alert turns off. A failed call is retried on the next tick.
func (a *capacityAllocator) alertBudget(ctx context.Context, now time.Time, epoch uint64, capacity budget.Capacity) {
	alert := &a.alert
	if alert.unsaved != nil {
		if err := a.saveAlert(ctx, epoch, *alert.unsaved); err != nil {
			a.alertFailed(ctx, now, epoch, err)
			return
		}
		alert.unsaved = nil
	}
	record, err := alert.load(ctx)
	if err != nil {
		a.alertFailed(ctx, now, epoch, err)
		return
	}
	if budget.Alerting(record.Open, capacity) == record.Open {
		alert.failure, alert.missing = "", false
		return
	}
	if err := a.global.authority.Guard(ctx, epoch); err != nil {
		a.alertFailed(ctx, now, epoch, err)
		return
	}
	next := alertRecord{At: now}
	if record.Open {
		err = alert.status.ResolveWarning(ctx, record.Incident)
	} else {
		next.Open = true
		next.Incident, err = alert.status.OpenWarning(ctx)
	}
	if err != nil {
		a.alertFailed(ctx, now, epoch, err)
		return
	}
	if err := a.saveAlert(ctx, epoch, next); err != nil {
		alert.unsaved = &next
		a.alertFailed(ctx, now, epoch, err)
		return
	}
	alert.failure, alert.missing = "", false
}

// saveAlert records the warning's state once the lease still holds.
func (a *capacityAllocator) saveAlert(ctx context.Context, epoch uint64, record alertRecord) error {
	if err := a.global.authority.Guard(ctx, epoch); err != nil {
		return err
	}
	return a.alert.save(ctx, record)
}

// alertFailed journals a missing operator token once and logs any other failure once per distinct message.
func (a *capacityAllocator) alertFailed(ctx context.Context, now time.Time, epoch uint64, err error) {
	alert := &a.alert
	if errors.Is(err, budget.ErrNoStatusToken) {
		if !alert.missing {
			alert.missing = true
			slog.Warn("ts-status warning not sent: no operator token in Vault", observability.ComponentKey, "budget")
			decisionlog.Record(ctx, decisionlog.Decision{Time: now, Region: "global", Epoch: epoch,
				Actor: decisionlog.Actor{Slice: "budget"}, Kind: decisionlog.KindHeld,
				Subject: decisionlog.Subject{Kind: "budget", ID: "monthly"}, Summary: "ts-status warning not sent",
				Reason: "no ts-status operator token in Vault"})
		}
		return
	}
	if alert.failure != err.Error() {
		alert.failure = err.Error()
		slog.Warn("ts-status budget warning failed", observability.ComponentKey, "budget", "error", err)
	}
}

// bucket opens TS_BUDGET_ALERT on first use.
func (b *budgetAlert) bucket(ctx context.Context) (jetstream.KeyValue, error) {
	if b.kv == nil {
		kv, err := b.js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: alertBucket,
			Description: "TS-804 ts-status budget warning state", History: 1, Replicas: max(b.replicas, 1),
			Storage: jetstream.FileStorage})
		if err != nil {
			return nil, fmt.Errorf("open %s bucket: %w", alertBucket, err)
		}
		b.kv = kv
	}
	return b.kv, nil
}

// load returns the stored record, or the zero record when none was saved yet.
func (b *budgetAlert) load(ctx context.Context) (alertRecord, error) {
	kv, err := b.bucket(ctx)
	if err != nil {
		return alertRecord{}, err
	}
	entry, err := kv.Get(ctx, alertKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return alertRecord{}, nil
	}
	if err != nil {
		return alertRecord{}, fmt.Errorf("read budget alert: %w", err)
	}
	var record alertRecord
	if err := protocol.DecodeStrict(entry.Value(), &record, maxAlertBytes); err != nil {
		return alertRecord{}, fmt.Errorf("decode budget alert: %w", err)
	}
	return record, nil
}

func (b *budgetAlert) save(ctx context.Context, record alertRecord) error {
	kv, err := b.bucket(ctx)
	if err != nil {
		return err
	}
	payload, err := protocol.EncodeJSON(record)
	if err != nil {
		return err
	}
	if _, err := kv.Put(ctx, alertKey, payload); err != nil {
		return fmt.Errorf("save budget alert: %w", err)
	}
	return nil
}
