package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"github.com/nats-io/nats.go/jetstream"
)

func registrationSubjectKey(cell, node string) string  { return cell + "." + node }
func desiredSubjectKey(cell, node, role string) string { return cell + "." + node + "." + role }

func rejectObsoleteRetirementState(ctx context.Context, state jetstream.KeyValue, cell string) error {
	keys, err := state.ListKeysFiltered(ctx, "retired."+cell+".>", "retirement-quarantine."+cell+".>", "retirement-cutover."+cell)
	if err != nil {
		return fmt.Errorf("validate host retirement storage: %w", err)
	}
	defer keys.Stop()
	obsolete := false
	for range keys.Keys() {
		obsolete = true
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if obsolete {
		return errors.New("host state contains obsolete retirement keys; updated host control cannot start over this state")
	}
	return nil
}

func (c *Controller) readRetirement(ctx context.Context, node string) (retirement, uint64, error) {
	if err := validateToken(node, "node"); err != nil {
		return retirement{}, 0, err
	}
	key := registrationSubjectKey(c.cell, node)
	entry, err := c.mutations.ReadHostMutation(ctx, authority.MutationRetirement, key)
	if errors.Is(err, authority.ErrNotFound) {
		return retirement{}, 0, nil
	}
	if err != nil {
		return retirement{}, 0, err
	}
	if entry.Kind != authority.MutationRetirement || entry.SubjectKey != key || entry.Sequence == 0 || entry.Epoch == 0 {
		return retirement{}, 0, errors.New("retirement log entry is malformed")
	}
	mark, err := decodeRetirement(entry.Payload)
	if err != nil {
		return retirement{}, 0, err
	}
	return mark, entry.Sequence, nil
}

func decodeRetirement(payload []byte) (retirement, error) {
	var value struct {
		Retired *bool `json:"retired"`
	}
	if err := decodeStrict(payload, &value); err != nil {
		return retirement{}, err
	}
	if value.Retired == nil {
		return retirement{}, errors.New("retirement record requires a non-null retired state")
	}
	return retirement{Retired: *value.Retired}, nil
}

func (c *Controller) readRegistration(ctx context.Context, node string) (Registration, uint64, bool, error) {
	if err := validateToken(node, "node"); err != nil {
		return Registration{}, 0, false, err
	}
	key := registrationSubjectKey(c.cell, node)
	entry, err := c.mutations.ReadHostMutation(ctx, authority.MutationRegistration, key)
	if errors.Is(err, authority.ErrNotFound) {
		return Registration{}, 0, false, nil
	}
	if err != nil {
		return Registration{}, 0, false, err
	}
	if entry.Kind != authority.MutationRegistration || entry.SubjectKey != key || entry.Sequence == 0 || entry.Epoch == 0 {
		return Registration{}, 0, false, errors.New("registration log entry is malformed")
	}
	var r Registration
	if err := decodeStrict(entry.Payload, &r); err != nil {
		return Registration{}, 0, false, err
	}
	if r.Node != node || r.ID != entityid.Derive("host", c.cell, node) {
		return Registration{}, 0, false, errors.New("registration log identity mismatch")
	}
	if err := validateRegistration(r, c.cell); err != nil {
		return Registration{}, 0, false, err
	}
	return r, entry.Sequence, true, nil
}

func (c *Controller) readDesired(ctx context.Context, node, role string) (Desired, uint64, bool, error) {
	if err := validateToken(node, "node"); err != nil {
		return Desired{}, 0, false, err
	}
	if err := validateToken(role, "role"); err != nil {
		return Desired{}, 0, false, err
	}
	key := desiredSubjectKey(c.cell, node, role)
	entry, err := c.mutations.ReadHostMutation(ctx, authority.MutationDesired, key)
	if errors.Is(err, authority.ErrNotFound) {
		return Desired{}, 0, false, nil
	}
	if err != nil {
		return Desired{}, 0, false, err
	}
	if entry.Kind != authority.MutationDesired || entry.SubjectKey != key || entry.Sequence == 0 || entry.Epoch == 0 {
		return Desired{}, 0, false, errors.New("desired log entry is malformed")
	}
	var d Desired
	if err := decodeStrict(entry.Payload, &d); err != nil {
		return Desired{}, 0, false, err
	}
	if d.Cell != c.cell || d.Node != node || d.Role != role || d.AuthorityEpoch != entry.Epoch {
		return Desired{}, 0, false, errors.New("desired log identity or epoch mismatch")
	}
	return d, entry.Sequence, true, nil
}

func mutationPayload(value any) ([]byte, string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	if len(data) > 64<<10 {
		return nil, "", errors.New("host mutation exceeds value limit")
	}
	hash := sha256.Sum256(data)
	return data, entityid.Derive("host-mutation", hex.EncodeToString(hash[:])), nil
}
