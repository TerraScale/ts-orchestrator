package alertdelivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/gofrs/flock"
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
	budgetDial          = 2 * time.Second
)

type withheld int

const (
	budgetExhausted withheld = iota
	budgetUnavailable
)

var errPushInFlight = errors.New("push in flight")

type emailBudget struct {
	withheld    [2]atomic.Uint64
	mu          sync.Mutex
	sched       sync.Mutex
	idle        *sync.Cond
	inflight    int
	live        net.Conn
	interrupted bool
	shared      *sharedStore
}

func newEmailBudget() *emailBudget {
	b := &emailBudget{}
	b.idle = sync.NewCond(&b.sched)
	return b
}

func (b *emailBudget) beginPush() {
	b.sched.Lock()
	b.inflight++
	conn := b.live
	if conn != nil {
		b.live = nil
		b.interrupted = true
	}
	b.sched.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (b *emailBudget) endPush() {
	b.sched.Lock()
	b.inflight--
	if b.inflight == 0 {
		b.idle.Broadcast()
	}
	b.sched.Unlock()
}

func (b *emailBudget) waitIdle(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() {
		b.sched.Lock()
		b.idle.Broadcast()
		b.sched.Unlock()
	})
	defer stop()
	b.sched.Lock()
	defer b.sched.Unlock()
	for b.inflight > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b.idle.Wait()
	}
	return nil
}

func (b *emailBudget) consumeInterrupt() bool {
	b.sched.Lock()
	defer b.sched.Unlock()
	hit := b.interrupted
	b.interrupted = false
	return hit
}

type budgetDialer struct {
	budget *emailBudget
	raw    net.Conn
}

func (d *budgetDialer) Dial(network, address string) (net.Conn, error) {
	raw, err := (&net.Dialer{Timeout: budgetDial}).Dial(network, address)
	if err != nil {
		return nil, err
	}
	d.budget.sched.Lock()
	defer d.budget.sched.Unlock()
	if d.budget.inflight > 0 {
		_ = raw.Close()
		d.budget.interrupted = true
		return nil, errPushInFlight
	}
	d.raw = raw
	d.budget.live = raw
	return raw, nil
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
	for {
		if err := b.waitIdle(ctx); err != nil {
			b.withheld[budgetUnavailable].Add(1)
			return "budget unavailable", err
		}
		b.mu.Lock()
		reason, err := b.reserveEmail(ctx, key, window)
		b.mu.Unlock()
		if err != nil && (errors.Is(err, errPushInFlight) || b.consumeInterrupt()) {
			continue
		}
		switch {
		case err != nil:
			b.withheld[budgetUnavailable].Add(1)
			return "budget unavailable", err
		case reason == "hourly cap" || reason == "daily cap":
			b.withheld[budgetExhausted].Add(1)
		}
		return reason, nil
	}
}

type reservationStore interface {
	load(context.Context) ([]emailReservation, uint64, error)
	save(context.Context, []byte, uint64) (bool, error)
	close()
}

func (b *emailBudget) openStore(ctx context.Context) (reservationStore, error) {
	if _, err := os.Stat(fleetLayout); errors.Is(err, os.ErrNotExist) {
		return openLedger(ctx, filepath.Join(stateDirectory, "email-ledger.json"))
	} else if err != nil {
		return nil, err
	}
	if b.shared != nil && !b.shared.conn.IsConnected() {
		b.shared.conn.Close()
		b.shared = nil
	}
	if b.shared != nil {
		return b.shared, nil
	}
	shared, err := b.openShared(ctx)
	if err != nil {
		return nil, err
	}
	b.shared = shared
	return shared, nil
}

func (b *emailBudget) reserveEmail(ctx context.Context, key string, window time.Duration) (string, error) {
	defer b.clearLive()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	store, err := b.openStore(ctx)
	if err != nil {
		return "", err
	}
	if shared, ok := store.(*sharedStore); ok {
		if err := b.track(shared.raw); err != nil {
			return "", err
		}
	}
	defer store.close()
	for {
		call, stop := context.WithTimeout(ctx, budgetDial)
		reservations, revision, err := store.load(call)
		stop()
		if err != nil {
			b.dropShared(store)
			return "", err
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
		call, stop = context.WithTimeout(ctx, budgetDial)
		conflict, err := store.save(call, data, revision)
		stop()
		if err != nil {
			b.dropShared(store)
		}
		if !conflict {
			return "", err
		}
	}
}

type sharedStore struct {
	conn   *nats.Conn
	raw    net.Conn
	bucket jetstream.KeyValue
}

func (b *emailBudget) track(conn net.Conn) error {
	b.sched.Lock()
	defer b.sched.Unlock()
	if b.inflight > 0 {
		b.interrupted = true
		return errPushInFlight
	}
	b.live = conn
	return nil
}

func (b *emailBudget) openShared(ctx context.Context) (*sharedStore, error) {
	values, err := readCredentialFiles("TS_ALERTS_NATS_TOKEN_FILE")
	if err != nil {
		return nil, err
	}
	dialer := &budgetDialer{budget: b}
	conn, err := nats.Connect(budgetServer, nats.UserInfo(mesh.AlertsUser, strings.TrimSpace(values["TS_ALERTS_NATS_TOKEN_FILE"])), nats.Name("ts-alerts"), nats.Timeout(budgetDial), nats.NoReconnect(), nats.SetCustomDialer(dialer))
	if err != nil {
		return nil, err
	}
	js, err := jetstream.New(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	bucket, err := js.KeyValue(ctx, budgetBucket)
	if errors.Is(err, jetstream.ErrBucketNotFound) {
		bucket, err = js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: budgetBucket, History: 1, Replicas: 3, MaxBytes: 4 << 20, MaxValueSize: 128 << 10, Storage: jetstream.FileStorage})
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &sharedStore{conn, dialer.raw, bucket}, nil
}

func (s *sharedStore) load(ctx context.Context) ([]emailReservation, uint64, error) {
	entry, err := s.bucket.Get(ctx, budgetKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	var reservations []emailReservation
	return reservations, entry.Revision(), json.Unmarshal(entry.Value(), &reservations)
}

func (s *sharedStore) save(ctx context.Context, data []byte, revision uint64) (bool, error) {
	_, err := s.bucket.Update(ctx, budgetKey, data, revision)
	var conflict *jetstream.APIError
	if errors.As(err, &conflict) && (conflict.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence || conflict.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequenceConstant) {
		return true, nil
	}
	return false, err
}

func (s *sharedStore) close() {}

func (b *emailBudget) clearLive() {
	b.sched.Lock()
	b.live = nil
	b.sched.Unlock()
}

func (b *emailBudget) dropShared(store reservationStore) {
	shared, ok := store.(*sharedStore)
	if !ok || b.shared != shared {
		return
	}
	shared.conn.Close()
	b.shared = nil
}

type ledgerStore struct {
	path string
	lock *flock.Flock
}

func openLedger(ctx context.Context, path string) (reservationStore, error) {
	lock := flock.New(path + ".lock")
	locked, err := lock.TryLockContext(ctx, 10*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, errors.New("email ledger locked")
	}
	return ledgerStore{path, lock}, nil
}

func (l ledgerStore) load(context.Context) ([]emailReservation, uint64, error) {
	data, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	var reservations []emailReservation
	return reservations, 0, json.Unmarshal(data, &reservations)
}

func (l ledgerStore) save(_ context.Context, data []byte, _ uint64) (bool, error) {
	file, err := os.CreateTemp(filepath.Dir(l.path), ".email-ledger-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return false, err
	}
	if err := os.Rename(file.Name(), l.path); err != nil {
		return false, err
	}
	dir, err := os.Open(filepath.Dir(l.path))
	if err != nil {
		return false, err
	}
	defer dir.Close()
	return false, dir.Sync()
}

func (l ledgerStore) close() { _ = l.lock.Unlock() }
