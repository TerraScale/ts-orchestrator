package alertdelivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	emailRepeatInterval = 4 * time.Hour
	digestInterval      = 24 * time.Hour
	fleetHourlyEmails   = 12
	fleetDailyEmails    = 288
	budgetBucket        = "ts-alert-email"
	budgetKey           = "ledger"
	digestKey           = "daily-digest"
)

type withheld int

const (
	budgetExhausted withheld = iota
	budgetUnavailable
)

type emailBudget struct {
	mu       sync.Mutex
	withheld [2]atomic.Uint64
}

type emailReservation struct {
	Key    string    `json:"key"`
	SendBy time.Time `json:"send_by"`
	Until  time.Time `json:"until"`
}

func (n notification) emailKey() string {
	identity := n.GroupKey
	if identity == "" {
		var fingerprints []string
		for _, alert := range n.Alerts {
			fingerprint := alert.Fingerprint
			if fingerprint == "" {
				labels, _ := json.Marshal(alert.Labels, json.Deterministic(true))
				fingerprint = string(labels)
			}
			fingerprints = append(fingerprints, fingerprint)
		}
		slices.Sort(fingerprints)
		identity = strings.Join(slices.Compact(fingerprints), "\n")
	}
	sum := sha256.Sum256([]byte(n.Status + "\x00" + identity))
	return hex.EncodeToString(sum[:])
}

func (b *emailBudget) write(w io.Writer) {
	fmt.Fprintln(w, "# HELP terrascale_alert_delivery_email_withheld_total Alert emails withheld because the fleet-wide email budget was exhausted or unreachable; push still delivered.")
	fmt.Fprintln(w, "# TYPE terrascale_alert_delivery_email_withheld_total counter")
	fmt.Fprintf(w, "terrascale_alert_delivery_email_withheld_total{reason=\"budget_exhausted\"} %d\n", b.withheld[budgetExhausted].Load())
	fmt.Fprintf(w, "terrascale_alert_delivery_email_withheld_total{reason=\"budget_unavailable\"} %d\n", b.withheld[budgetUnavailable].Load())
}

func (b *emailBudget) reserve(ctx context.Context, key string, window time.Duration) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	reason, err := b.reserveShared(ctx, key, window)
	switch {
	case err != nil:
		b.withheld[budgetUnavailable].Add(1)
		return "budget unavailable", err
	case reason == "hourly cap" || reason == "daily cap":
		b.withheld[budgetExhausted].Add(1)
	}
	return reason, nil
}

func (b *emailBudget) reserveShared(ctx context.Context, key string, window time.Duration) (string, error) {
	values, err := readCredentialFiles("TS_ALERTS_NATS_TOKEN_FILE")
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(values["TS_ALERTS_NATS_TOKEN_FILE"])
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := nats.Connect(budgetServer, nats.UserInfo(mesh.AlertsUser, token), nats.Name("ts-alerts"), nats.Timeout(2*time.Second), nats.NoReconnect())
	if err != nil {
		return "", err
	}
	defer conn.Close()
	js, err := jetstream.New(conn)
	if err != nil {
		return "", err
	}
	bucket, err := js.KeyValue(ctx, budgetBucket)
	if errors.Is(err, jetstream.ErrBucketNotFound) {
		bucket, err = js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: budgetBucket, History: 1, Replicas: 3, MaxBytes: 4 << 20, MaxValueSize: 128 << 10, Storage: jetstream.FileStorage})
	}
	if err != nil {
		return "", err
	}
	for {
		var reservations []emailReservation
		var revision uint64
		entry, err := bucket.Get(ctx, budgetKey)
		switch {
		case errors.Is(err, jetstream.ErrKeyNotFound):
		case err != nil:
			return "", err
		default:
			revision = entry.Revision()
			if err := json.Unmarshal(entry.Value(), &reservations); err != nil {
				return "", err
			}
		}
		now := time.Now()
		reservations = slices.DeleteFunc(reservations, func(v emailReservation) bool { return !v.Until.After(now) && !v.SendBy.Add(24*time.Hour).After(now) })
		hourly, daily := 0, 0
		for _, entry := range reservations {
			if entry.Key == key && entry.Until.After(now) {
				return "duplicate", nil
			}
			if entry.SendBy.Add(24 * time.Hour).After(now) {
				daily++
			}
			if entry.SendBy.Add(time.Hour).After(now) {
				hourly++
			}
		}
		if hourly >= fleetHourlyEmails {
			return "hourly cap", nil
		}
		if daily >= fleetDailyEmails {
			return "daily cap", nil
		}
		sendBy := now.Add(50 * time.Second)
		data, err := json.Marshal(append(reservations, emailReservation{Key: key, SendBy: sendBy, Until: sendBy.Add(window)}))
		if err != nil {
			return "", err
		}
		_, err = bucket.Update(ctx, budgetKey, data, revision)
		var conflict *jetstream.APIError
		if errors.As(err, &conflict) && (conflict.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence || conflict.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequenceConstant) {
			continue
		}
		return "", err
	}
}
