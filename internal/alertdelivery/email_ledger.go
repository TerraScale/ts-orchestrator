package alertdelivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

// Match production/alertmanager.yml. These limits are shared by every group and
// status in the single production relay, leaving sign-in emails the daily quota.
const emailRepeatInterval = 4 * time.Hour
const digestInterval = 24 * time.Hour
const emailHourlyLimit = 12

// Every warning shares one digest identity, whatever Alertmanager regrouped.
const digestKey = "daily-digest"

type emailReservation struct {
	Key    string    `json:"key"`
	SendBy time.Time `json:"send_by"`
	// Until is absent in ledgers written before digests; those used the repeat window.
	Until time.Time `json:"until,omitzero"`
}

func (v emailReservation) expiry() time.Time {
	if v.Until.IsZero() {
		return v.SendBy.Add(emailRepeatInterval)
	}
	return v.Until
}

func (n notification) emailKey() string {
	identity := n.GroupKey
	if identity == "" {
		// Alertmanager supplies groupKey; older callers fall back to a stable,
		// order-independent set of fingerprints (or full labels if absent).
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

// Reserve before contacting Cloudflare: a lost response must not spend a second
// quota slot. Persist attempts even on errors. File locking covers concurrent
// requests and overlapping relay processes; restart never resets the budget.
func (r relay) reserveEmail(ctx context.Context, key string, window time.Duration, now time.Time) string {
	lock := flock.New(r.ledgerPath + ".lock")
	locked, err := lock.TryLockContext(ctx, 10*time.Millisecond)
	if err != nil || !locked {
		return "ledger unavailable"
	}
	defer lock.Unlock()
	data, err := os.ReadFile(r.ledgerPath)
	var reservations []emailReservation
	if err != nil && !errors.Is(err, os.ErrNotExist) || err == nil && json.Unmarshal(data, &reservations) != nil {
		return "ledger unavailable"
	}
	reservations = slices.DeleteFunc(reservations, func(v emailReservation) bool { return !v.expiry().After(now) })
	count := 0
	for _, entry := range reservations {
		if entry.Key == key {
			return "duplicate"
		}
		if entry.SendBy.Add(time.Hour).After(now) {
			count++
		}
	}
	if count >= emailHourlyLimit {
		return "hourly cap"
	}
	// The context bounds locking, Vault reads and provider delivery. Expire from
	// its deadline, not reservation time, so delayed sends cannot overlap the
	// next hourly or repeat window. A crash still leaves this reservation intact.
	sendBy := now
	if deadline, ok := ctx.Deadline(); ok && deadline.After(sendBy) {
		sendBy = deadline
	}
	reservations = append(reservations, emailReservation{Key: key, SendBy: sendBy, Until: sendBy.Add(window)})
	data, err = json.Marshal(reservations)
	if err != nil {
		return "ledger unavailable"
	}
	file, err := os.CreateTemp(filepath.Dir(r.ledgerPath), ".email-ledger-*")
	if err != nil {
		return "ledger unavailable"
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || os.Rename(file.Name(), r.ledgerPath) != nil {
		return "ledger unavailable"
	}
	dir, err := os.Open(filepath.Dir(r.ledgerPath))
	if err != nil {
		return "ledger unavailable"
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return "ledger unavailable"
	}
	return ""
}
