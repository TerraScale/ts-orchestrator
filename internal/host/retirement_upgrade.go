package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const RetirementQuarantineSchema = "terrascale.host.retirement-quarantine.v1"
const RetirementCutoverSchema = "terrascale.host.retirement-cutover.v1"

var ErrRetirementCutoverPending = errors.New("retirement storage cutover has not been authorized")

// RetirementQuarantine is an operator's permanent ban on one retired identity.
// It pins, and never changes, the legacy safety mark retained for old controllers.
type RetirementQuarantine struct {
	Schema         string `json:"schema"`
	Cell           string `json:"cell"`
	Node           string `json:"node"`
	LegacyKey      string `json:"legacy_key"`
	LegacyRevision uint64 `json:"legacy_revision"`
	LegacySHA256   string `json:"legacy_sha256"`
}

type retirementQuarantineEntry struct {
	RetirementQuarantine
	Revision uint64 `json:"quarantine_revision"`
	SHA256   string `json:"quarantine_sha256"`
}

// RetirementCutover enables ordinary retirement writes after an operator has
// verified that every controller uses ordered retirement storage.
type RetirementCutover struct {
	Schema              string `json:"schema"`
	Cell                string `json:"cell"`
	QuarantineSetSHA256 string `json:"quarantine_set_sha256"`
}

func quarantineKey(cell, node string) string { return "retirement-quarantine." + cell + "." + node }
func cutoverKey(cell string) string          { return "retirement-cutover." + cell }

func retirementStateEntry(ctx context.Context, conn *nats.Conn, key string) (*nats.RawStreamMsg, error) {
	js, err := conn.JetStream()
	if err != nil {
		return nil, err
	}
	subject := "$KV." + stateBucket + "." + key
	entry, err := js.GetLastMsg("KV_"+stateBucket, subject, nats.Context(ctx))
	if errors.Is(err, nats.ErrMsgNotFound) {
		return nil, jetstream.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	if entry == nil || entry.Subject != subject || entry.Sequence == 0 || len(entry.Data) > 64<<10 {
		return nil, errors.New("invalid retirement storage entry")
	}
	if op := entry.Header.Get("KV-Operation"); op == "DEL" || op == "PURGE" {
		return nil, jetstream.ErrKeyNotFound
	} else if op != "" || entry.Header.Get(jetstream.MarkerReasonHeader) != "" {
		return nil, errors.New("invalid retirement storage operation")
	}
	return entry, nil
}

func validateQuarantine(ctx context.Context, conn *nats.Conn, claim RetirementQuarantine) error {
	if claim.Schema != RetirementQuarantineSchema || validateToken(claim.Cell, "cell") != nil ||
		validateToken(claim.Node, "node") != nil || claim.LegacyRevision == 0 ||
		claim.LegacyKey != "retired."+claim.Cell+"."+claim.Node || validateDigest(claim.LegacySHA256) != nil {
		return errors.New("invalid retirement quarantine scope or pins")
	}
	entry, err := retirementStateEntry(ctx, conn, claim.LegacyKey)
	if err != nil {
		return fmt.Errorf("read quarantined retirement: %w", err)
	}
	digest := sha256.Sum256(entry.Data)
	if entry.Sequence != claim.LegacyRevision || hex.EncodeToString(digest[:]) != claim.LegacySHA256 {
		return errors.New("quarantined retirement revision or digest changed")
	}
	var legacy struct {
		Retired *bool     `json:"retired"`
		At      time.Time `json:"at"`
	}
	if err := decodeStrict(entry.Data, &legacy); err != nil {
		return err
	}
	if legacy.Retired == nil || !*legacy.Retired || legacy.At.IsZero() {
		return errors.New("retirement quarantine requires an active, timestamped legacy mark")
	}
	return nil
}

func loadRetirementQuarantines(ctx context.Context, conn *nats.Conn, state jetstream.KeyValue, cell string) (map[string]retirementQuarantineEntry, error) {
	keys, err := state.ListKeysFiltered(ctx, "retired."+cell+".>", "retirement-quarantine."+cell+".>")
	if err != nil {
		return nil, fmt.Errorf("validate host retirement storage: %w", err)
	}
	defer keys.Stop()
	claims := make(map[string]retirementQuarantineEntry)
	var legacyKeys []string
	for key := range keys.Keys() {
		if strings.HasPrefix(key, "retired.") {
			legacyKeys = append(legacyKeys, key)
			continue
		}
		entry, err := retirementStateEntry(ctx, conn, key)
		if err != nil {
			return nil, err
		}
		var claim RetirementQuarantine
		if err := decodeStrict(entry.Data, &claim); err != nil {
			return nil, err
		}
		if claim.Cell != cell || key != quarantineKey(cell, claim.Node) {
			return nil, errors.New("retirement quarantine identity mismatch")
		}
		// Claims are validated independently: deleting the legacy key cannot
		// make its permanent quarantine disappear from startup validation.
		if err := validateQuarantine(ctx, conn, claim); err != nil {
			return nil, err
		}
		digest := sha256.Sum256(entry.Data)
		claims[claim.Node] = retirementQuarantineEntry{claim, entry.Sequence, hex.EncodeToString(digest[:])}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, key := range legacyKeys {
		claim, ok := claims[strings.TrimPrefix(key, "retired."+cell+".")]
		if !ok || claim.LegacyKey != key {
			return nil, errors.New("host state contains obsolete retirement keys without an explicit quarantine")
		}
	}
	return claims, nil
}

func quarantineSetDigest(claims map[string]retirementQuarantineEntry) string {
	entries := make([]retirementQuarantineEntry, 0, len(claims))
	for _, claim := range claims {
		entries = append(entries, claim)
	}
	slices.SortFunc(entries, func(a, b retirementQuarantineEntry) int { return strings.Compare(a.Node, b.Node) })
	data, _ := json.Marshal(entries)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// CreateRetirementQuarantine pins a verified active mark without changing it.
// Operators must first verify that the identity has been permanently retired.
func CreateRetirementQuarantine(ctx context.Context, js jetstream.JetStream, claim RetirementQuarantine) (uint64, error) {
	if err := validateQuarantine(ctx, js.Conn(), claim); err != nil {
		return 0, err
	}
	state, err := js.KeyValue(ctx, stateBucket)
	if err != nil {
		return 0, err
	}
	data, err := json.Marshal(claim)
	if err != nil {
		return 0, err
	}
	return state.Create(ctx, quarantineKey(claim.Cell, claim.Node), data)
}

// RetirementQuarantineSetSHA256 binds the complete validated claim set,
// including each claim's KV revision and exact bytes.
func RetirementQuarantineSetSHA256(ctx context.Context, js jetstream.JetStream, cell string) (string, error) {
	if err := validateToken(cell, "cell"); err != nil {
		return "", err
	}
	state, err := js.KeyValue(ctx, stateBucket)
	if err != nil {
		return "", err
	}
	claims, err := loadRetirementQuarantines(ctx, js.Conn(), state, cell)
	if err != nil {
		return "", err
	}
	return quarantineSetDigest(claims), nil
}

// AuthorizeRetirementCutover requires the exact reviewed claim set. A zero
// previousRevision creates the marker; replacing one requires its KV revision.
// The operator must independently verify all controllers have been upgraded.
func AuthorizeRetirementCutover(ctx context.Context, js jetstream.JetStream, cell, expectedSetSHA256 string, previousRevision uint64) (uint64, error) {
	digest, err := RetirementQuarantineSetSHA256(ctx, js, cell)
	if err != nil {
		return 0, err
	}
	if expectedSetSHA256 != digest {
		return 0, errors.New("retirement quarantine set changed")
	}
	state, err := js.KeyValue(ctx, stateBucket)
	if err != nil {
		return 0, err
	}
	data, err := json.Marshal(RetirementCutover{RetirementCutoverSchema, cell, digest})
	if err != nil {
		return 0, err
	}
	if previousRevision == 0 {
		return state.Create(ctx, cutoverKey(cell), data)
	}
	return state.Update(ctx, cutoverKey(cell), data, previousRevision)
}

func (c *Controller) requireRetirementCutover(ctx context.Context) error {
	if c.state == nil && len(c.quarantines) == 0 { // Connectionless package fixtures have no legacy state.
		return nil
	}
	claims, err := loadRetirementQuarantines(ctx, c.conn, c.state, c.cell)
	if err != nil {
		return err
	}
	if len(claims) == 0 && len(c.quarantines) == 0 {
		return nil
	}
	if quarantineSetDigest(claims) != quarantineSetDigest(c.quarantines) {
		return ErrRetirementCutoverPending
	}
	entry, err := retirementStateEntry(ctx, c.conn, cutoverKey(c.cell))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRetirementCutoverPending, err)
	}
	var cutover RetirementCutover
	if err := decodeStrict(entry.Data, &cutover); err != nil {
		return err
	}
	if cutover.Schema != RetirementCutoverSchema || cutover.Cell != c.cell || cutover.QuarantineSetSHA256 != quarantineSetDigest(claims) {
		return ErrRetirementCutoverPending
	}
	return nil
}

func (c *Controller) importRetirementQuarantines(ctx context.Context) error {
	epoch := c.authorityEpoch()
	for node, claim := range c.quarantines {
		if err := c.guard(ctx, epoch); err != nil {
			return err
		}
		if err := c.validateQuarantineEntry(ctx, claim); err != nil {
			return err
		}
		key := registrationSubjectKey(c.cell, node)
		entry, err := c.mutations.ReadHostMutation(ctx, authority.MutationRetirement, key)
		if err != nil && !errors.Is(err, authority.ErrNotFound) {
			return err
		}
		operation := quarantineImportOperation(claim)
		if err == nil && entry.OperationID == operation {
			mark, err := decodeRetirement(entry.Payload)
			if err != nil || !mark.Retired {
				return errors.New("retirement quarantine import changed")
			}
			continue
		}
		payload := []byte(`{"retired":true}`)
		verify := func(verifyCtx context.Context) error { return c.validateQuarantineEntry(verifyCtx, claim) }
		verified, ok := c.mutations.(authority.VerifiedHostMutationStore)
		if !ok {
			return errors.New("retirement quarantine import requires a final verifier fence")
		}
		_, err = verified.CommitHostMutationVerified(ctx, epoch, authority.MutationRetirement, key, operation, entry.Sequence, payload, verify)
		if err != nil {
			return err
		}
	}
	return nil
}

func quarantineImportOperation(claim retirementQuarantineEntry) string {
	return "quarantine-" + claim.SHA256[:48]
}

func (c *Controller) validateQuarantineEntry(ctx context.Context, claim retirementQuarantineEntry) error {
	entry, err := retirementStateEntry(ctx, c.conn, quarantineKey(claim.Cell, claim.Node))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(entry.Data)
	if entry.Sequence != claim.Revision || hex.EncodeToString(digest[:]) != claim.SHA256 {
		return errors.New("retirement quarantine claim changed")
	}
	return validateQuarantine(ctx, c.conn, claim.RetirementQuarantine)
}

func (c *Controller) quarantineHistoryFloor(ctx context.Context) (time.Time, error) {
	var floor time.Time
	for node, claim := range c.quarantines {
		entry, err := c.mutations.ReadHostMutation(ctx, authority.MutationRetirement, registrationSubjectKey(c.cell, node))
		if err != nil {
			return floor, fmt.Errorf("retirement history import unavailable: %w", err)
		}
		mark, err := decodeRetirement(entry.Payload)
		if err != nil || !mark.Retired || entry.CreatedAt.IsZero() || entry.OperationID != quarantineImportOperation(claim) ||
			entry.Kind != authority.MutationRetirement || entry.SubjectKey != registrationSubjectKey(c.cell, node) || entry.Sequence == 0 || entry.Epoch == 0 {
			return floor, errors.New("retirement history import is missing or changed")
		}
		floor = laterTime(floor, entry.CreatedAt)
	}
	return floor, nil
}
