package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type nativeOwnerTarget struct {
	Node                 string `json:"node"`
	Generation           uint64 `json:"generation"`
	DesiredSHA256        string `json:"desired_sha256"`
	Digest               string `json:"digest"`
	WithdrawalGeneration uint64 `json:"withdrawal_generation"`
}

type runtimeOwner struct {
	Cell                  string                  `json:"cell"`
	Environment           string                  `json:"environment"`
	Role                  string                  `json:"role"`
	AuthorityEpoch        uint64                  `json:"authority_epoch"`
	Phase                 string                  `json:"phase"`
	AuthorizedBy          string                  `json:"authorized_by"`
	MigrationSHA256       string                  `json:"migration_sha256"`
	WorkloadGenesisSHA256 string                  `json:"workload_genesis_sha256,omitempty"`
	Genesis               release.WorkloadGenesis `json:"genesis,omitzero"`
	Retained              release.SequenceFloor   `json:"retained"`
	Targets               []nativeOwnerTarget     `json:"targets"`
	Stopped               []Report                `json:"stopped,omitempty"`
}

func runtimeOwnerKey(cell, environment, role string) string {
	return cell + "." + environment + "." + role
}

func (c *Controller) guardNativeOwner(ctx context.Context, environment, role string) error {
	if validateToken(environment, "environment") != nil || validateToken(role, "role") != nil {
		return errors.New("native runtime ownership scope is invalid")
	}
	_, err := c.mutations.ReadHostMutation(ctx, authority.MutationRuntimeOwner, runtimeOwnerKey(c.cell, environment, role))
	if errors.Is(err, authority.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("native workload is permanently fenced by container runtime ownership")
}

func (c *Controller) readRuntimeOwner(ctx context.Context, environment, role string) (runtimeOwner, authority.LogEntry, error) {
	key := runtimeOwnerKey(c.cell, environment, role)
	entry, err := c.mutations.ReadHostMutation(ctx, authority.MutationRuntimeOwner, key)
	if err != nil {
		return runtimeOwner{}, entry, err
	}
	var owner runtimeOwner
	if err := protocol.DecodeStrict(entry.Payload, &owner, 64<<10); err != nil {
		return owner, entry, err
	}
	if entry.Kind != authority.MutationRuntimeOwner || entry.SubjectKey != key || entry.Sequence == 0 || entry.Epoch == 0 ||
		owner.Cell != c.cell || owner.Environment != environment || owner.Role != role || owner.Role == terrabase.Role ||
		owner.AuthorityEpoch != entry.Epoch || owner.Phase != "native-fenced" && owner.Phase != "container" ||
		!lowerHex(owner.AuthorizedBy, 64) || len(owner.Targets) > 64 || owner.Phase == "native-fenced" && len(owner.Stopped) != 0 ||
		owner.Phase == "container" && len(owner.Stopped) != len(owner.Targets) {
		return owner, entry, errors.New("runtime ownership record is invalid")
	}
	if owner.WorkloadGenesisSHA256 != "" {
		if !lowerHex(owner.WorkloadGenesisSHA256, 64) || owner.AuthorizedBy != owner.WorkloadGenesisSHA256 || owner.MigrationSHA256 != "" || owner.Retained != (release.SequenceFloor{}) || len(owner.Targets) != 0 || len(owner.Stopped) != 0 || owner.Phase != "container" || owner.Genesis.Validate() != nil || owner.Genesis.Cell != strings.ToUpper(c.cell) || owner.Genesis.Environment != environment || owner.Genesis.Role != role {
			return owner, entry, errors.New("genesis runtime ownership record is invalid")
		}
		return owner, entry, nil
	}
	if owner.Genesis != (release.WorkloadGenesis{}) || !lowerHex(owner.MigrationSHA256, 64) || owner.Retained.Cell != strings.ToUpper(c.cell) || owner.Retained.RunNumber < 0 || owner.Retained.IssuedAt.IsZero() || !lowerHex(owner.Retained.EvidenceSHA256, 64) || len(owner.Targets) == 0 {
		return owner, entry, errors.New("native runtime ownership provenance is invalid")
	}
	for i, target := range owner.Targets {
		if validateToken(target.Node, "node") != nil || target.Generation == 0 || !lowerHex(target.DesiredSHA256, 64) ||
			target.WithdrawalGeneration < target.Generation || target.WithdrawalGeneration-target.Generation > 1 ||
			target.WithdrawalGeneration == target.Generation && target.Digest != "" ||
			target.WithdrawalGeneration != target.Generation && !lowerHex(target.Digest, 64) ||
			i > 0 && owner.Targets[i-1].Node >= target.Node {
			return owner, entry, errors.New("runtime ownership target is invalid")
		}
		if owner.Phase == "container" {
			report := owner.Stopped[i]
			if report.Cell != c.cell || report.Node != target.Node || report.Environment != environment || report.Role != role ||
				report.Generation != target.WithdrawalGeneration || report.Digest != "" || report.State != "stopped" || report.Error != "" ||
				report.SessionID == "" || report.Epoch == 0 || report.ObservedAt.IsZero() || report.Managed != nil {
				return owner, entry, errors.New("runtime ownership stopped receipt is invalid")
			}
		}
	}
	return owner, entry, nil
}

func (c *Controller) nativeOwnerInventory(ctx context.Context, environment, role string) ([]nativeOwnerTarget, error) {
	desired, err := c.ListDesired(ctx, role)
	if err != nil {
		return nil, err
	}
	var targets []nativeOwnerTarget
	for _, d := range desired {
		if d.Environment != environment {
			continue
		}
		if d.ManagedMember != nil || d.Role == terrabase.Role || d.Generation == 0 || !d.Withdrawn && d.Generation == ^uint64(0) {
			return nil, errors.New("native runtime handoff cannot migrate managed members or exhausted generations")
		}
		wire, _, err := mutationPayload(d)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(wire)
		generation := d.Generation
		if !d.Withdrawn {
			generation++
		}
		targets = append(targets, nativeOwnerTarget{Node: d.Node, Generation: d.Generation, DesiredSHA256: hex.EncodeToString(digest[:]), Digest: d.Digest, WithdrawalGeneration: generation})
	}
	if len(targets) == 0 || len(targets) > 64 {
		return nil, errors.New("native runtime handoff requires a bounded authenticated native desired inventory")
	}
	return targets, nil
}

func (c *Controller) ownerWithdrawals(ctx context.Context, owner runtimeOwner) error {
	desired, err := c.ListDesired(ctx, owner.Role)
	if err != nil {
		return err
	}
	count := 0
	for _, d := range desired {
		if d.Environment != owner.Environment {
			continue
		}
		if count >= len(owner.Targets) || d.Node != owner.Targets[count].Node || d.Generation != owner.Targets[count].WithdrawalGeneration ||
			!d.Withdrawn || d.ManagedMember != nil || d.Digest != "" || len(d.Args) != 0 || len(d.Env) != 0 || len(d.Secrets) != 0 {
			return errors.New("native owner withdrawal changed or remains active")
		}
		count++
	}
	if count != len(owner.Targets) {
		return errors.New("native owner withdrawal inventory is incomplete")
	}
	return nil
}

func (c *Controller) ownerStopped(ctx context.Context, owner runtimeOwner) ([]Report, error) {
	if err := c.ownerWithdrawals(ctx, owner); err != nil {
		return nil, err
	}
	statuses, err := c.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	stopped := make([]Report, 0, len(owner.Targets))
	for _, target := range owner.Targets {
		found := false
		for _, status := range statuses {
			if !status.Verified || status.Registration.Node != target.Node || status.Registration.Environment != owner.Environment ||
				status.Registration.ManagedMember != nil || !time.Now().Before(status.SessionExpiresAt) {
				continue
			}
			for _, report := range status.Reports {
				if report.Role == owner.Role && report.Generation == target.WithdrawalGeneration && report.Digest == "" &&
					report.State == "stopped" && report.Error == "" && report.Managed == nil {
					stopped = append(stopped, report)
					found = true
					break
				}
			}
		}
		if !found {
			return nil, fmt.Errorf("native owner %s lacks an authenticated current stopped receipt", target.Node)
		}
	}
	return stopped, nil
}

// GuardContainerOwner reads the durable stopped proof, not session absence.
// Identity resets cannot replace this record or reopen its native role.
func (c *Controller) GuardContainerOwner(ctx context.Context, environment, role string) error {
	owner, _, err := c.readRuntimeOwner(ctx, environment, role)
	if err != nil {
		return err
	}
	if owner.Phase != "container" {
		return errors.New("native runtime handoff has not completed")
	}
	if owner.WorkloadGenesisSHA256 != "" {
		return c.genesisNativeAbsent(ctx, environment, role)
	}
	return c.ownerWithdrawals(ctx, owner)
}

func (c *Controller) genesisNativeAbsent(ctx context.Context, environment, role string) error {
	desired, err := c.ListDesired(ctx, role)
	if err != nil {
		return err
	}
	for _, target := range desired {
		if target.Environment == environment {
			return errors.New("original genesis cannot replace existing native desired history")
		}
	}
	return nil
}

// ClaimGenesisContainer fences generic native admission before its first start.
// Zero native targets are authorized by the root genesis, never by empty inventory.
func (c *Controller) ClaimGenesisContainer(ctx context.Context, genesis release.VerifiedWorkloadGenesis, guard func(context.Context) error) error {
	origin := genesis.Origin()
	if c == nil || c.readOnly || guard == nil || !genesis.IsVerified() || origin.Cell != strings.ToUpper(c.cell) || origin.Role == terrabase.Role || origin.Role != "ts-auth" && origin.Role != "function-worker" {
		return errors.New("genesis owner requires authenticated generic original scope")
	}
	store, ok := c.mutations.(authority.VerifiedHostMutationStore)
	if !ok {
		return errors.New("genesis owner requires the final ordered mutation verifier")
	}
	if err := guard(ctx); err != nil {
		return err
	}
	owner, _, err := c.readRuntimeOwner(ctx, origin.Environment, origin.Role)
	if errors.Is(err, authority.ErrNotFound) {
		epoch := c.authorityEpoch()
		owner = runtimeOwner{Cell: c.cell, Environment: origin.Environment, Role: origin.Role, AuthorityEpoch: epoch, Phase: "container", AuthorizedBy: genesis.Fingerprint(), WorkloadGenesisSHA256: genesis.Fingerprint(), Genesis: origin}
		wire, operation, err := mutationPayload(owner)
		if err != nil {
			return err
		}
		_, err = store.CommitHostMutationVerified(ctx, epoch, authority.MutationRuntimeOwner, runtimeOwnerKey(c.cell, origin.Environment, origin.Role), operation, 0, wire, func(check context.Context) error {
			if err := guard(check); err != nil {
				return err
			}
			if err := c.genesisNativeAbsent(check, origin.Environment, origin.Role); err != nil {
				return err
			}
			return c.guard(check, epoch)
		})
		if err != nil {
			return err
		}
		owner, _, err = c.readRuntimeOwner(ctx, origin.Environment, origin.Role)
	}
	if err != nil {
		return err
	}
	if owner.WorkloadGenesisSHA256 != genesis.Fingerprint() || owner.Genesis != origin {
		return errors.New("original genesis differs from permanent generic runtime owner")
	}
	if err := c.GuardContainerOwner(ctx, origin.Environment, origin.Role); err != nil {
		return err
	}
	return guard(ctx)
}

// HandoffGenesisToContainer authenticates the previously installed origin owner.
// It creates no native migration floor or fabricated stopped receipt.
func (c *Controller) HandoffGenesisToContainer(ctx context.Context, verified release.VerifiedContainer, guard func(context.Context) error) (func(context.Context) error, error) {
	genesis := verified.Genesis()
	check := func(ctx context.Context) error {
		if !verified.Valid(time.Now().UTC()) || !genesis.IsVerified() {
			return errors.New("genesis handoff requires current verified release authority")
		}
		if err := guard(ctx); err != nil {
			return err
		}
		owner, _, err := c.readRuntimeOwner(ctx, genesis.Origin().Environment, genesis.Origin().Role)
		if err != nil {
			return err
		}
		if owner.Genesis != genesis.Origin() || owner.WorkloadGenesisSHA256 != genesis.Fingerprint() {
			return errors.New("genesis release lacks its original permanent generic runtime owner")
		}
		if err := c.GuardContainerOwner(ctx, genesis.Origin().Environment, genesis.Origin().Role); err != nil {
			return err
		}
		return guard(ctx)
	}
	if c == nil || guard == nil {
		return nil, errors.New("genesis handoff requires generic host authority")
	}
	return check, check(ctx)
}

// HandoffToContainer permanently fences native admission before withdrawing it.
// Each stop is acknowledged by the admitted host session before container effects.
func (c *Controller) HandoffToContainer(ctx context.Context, verified release.VerifiedContainer, roots trust.Keyring,
	retained release.SequenceFloor, guard func(context.Context) error,
) (func(context.Context) error, error) {
	if c == nil || c.readOnly || c.mutations == nil || guard == nil {
		return nil, errors.New("native runtime handoff requires mutable authenticated host authority")
	}
	store, ok := c.mutations.(authority.VerifiedHostMutationStore)
	if !ok {
		return nil, errors.New("native runtime handoff requires the final ordered verifier fence")
	}
	claim := verified.Claim()
	if verified.Genesis().IsVerified() {
		return nil, errors.New("genesis requires its explicit prospective ownership path")
	}
	if claim.Cell != strings.ToUpper(c.cell) || claim.Role == terrabase.Role || validateToken(claim.Role, "role") != nil || validateToken(claim.Environment, "environment") != nil {
		return nil, errors.New("native runtime handoff target is invalid")
	}
	epoch := c.authorityEpoch()
	authorized := func(ctx context.Context) error {
		if !verified.Valid(time.Now().UTC()) {
			return errors.New("native runtime handoff requires a current verified container release")
		}
		migration, err := release.VerifySequenceMigrationCurrent(verified.MigrationEnvelope(), roots, claim.Role, claim.Environment, time.Now().UTC())
		if err != nil {
			return err
		}
		if retained.Cell != claim.Cell || retained.RunNumber < 0 || retained.IssuedAt.IsZero() || !lowerHex(retained.EvidenceSHA256, 64) ||
			!migration.AdmitsLegacyFloor(retained.Cell, retained.RunNumber, retained.IssuedAt) {
			return errors.New("signed migration does not cover authenticated retained native release")
		}
		if err := guard(ctx); err != nil {
			return err
		}
		return c.guard(ctx, epoch)
	}
	if err := authorized(ctx); err != nil {
		return nil, err
	}
	owner, entry, err := c.readRuntimeOwner(ctx, claim.Environment, claim.Role)
	if errors.Is(err, authority.ErrNotFound) {
		targets, err := c.nativeOwnerInventory(ctx, claim.Environment, claim.Role)
		if err != nil {
			return nil, err
		}
		owner = runtimeOwner{Cell: c.cell, Environment: claim.Environment, Role: claim.Role, AuthorityEpoch: epoch,
			Phase: "native-fenced", AuthorizedBy: verified.Fingerprint(), MigrationSHA256: claim.SequenceMigrationSHA256, Retained: retained, Targets: targets}
		wire, operation, err := mutationPayload(owner)
		if err != nil {
			return nil, err
		}
		_, err = store.CommitHostMutationVerified(ctx, epoch, authority.MutationRuntimeOwner,
			runtimeOwnerKey(c.cell, claim.Environment, claim.Role), operation, 0, wire, func(check context.Context) error {
				current, err := c.nativeOwnerInventory(check, claim.Environment, claim.Role)
				if err != nil {
					return err
				}
				if !sameJSON(current, targets) {
					return errors.New("native runtime inventory changed before owner fence")
				}
				return authorized(check)
			})
		if err != nil {
			return nil, err
		}
		owner, entry, err = c.readRuntimeOwner(ctx, claim.Environment, claim.Role)
	}
	if err != nil {
		return nil, err
	}
	if !verified.Migration().AdmitsLegacyFloor(owner.Retained.Cell, owner.Retained.RunNumber, owner.Retained.IssuedAt) {
		return nil, errors.New("current signed migration does not cover original native handoff")
	}
	if owner.Phase == "native-fenced" {
		for _, target := range owner.Targets {
			if err := authorized(ctx); err != nil {
				return nil, err
			}
			d, _, exists, err := c.readDesired(ctx, target.Node, claim.Role)
			if err != nil || !exists {
				return nil, errors.Join(err, errors.New("pinned native desired is unavailable"))
			}
			if d.Withdrawn && d.Environment == claim.Environment && d.Generation == target.WithdrawalGeneration && d.ManagedMember == nil {
				continue
			}
			wire, _, err := mutationPayload(d)
			if err != nil {
				return nil, err
			}
			digest := sha256.Sum256(wire)
			if d.Environment != claim.Environment || d.ManagedMember != nil || d.Generation != target.Generation || hex.EncodeToString(digest[:]) != target.DesiredSHA256 {
				return nil, errors.New("pinned native desired changed during handoff")
			}
			withdrawal := Desired{Cell: c.cell, Node: target.Node, Environment: claim.Environment, Role: claim.Role,
				Generation: target.WithdrawalGeneration, AuthorityEpoch: epoch, Withdrawn: true}
			if _, err := c.ApplyDesired(ctx, withdrawal); err != nil {
				return nil, err
			}
		}
		stopped, err := c.ownerStopped(ctx, owner)
		if err != nil {
			return nil, err
		}
		owner.Phase, owner.AuthorityEpoch, owner.Stopped = "container", epoch, stopped
		wire, operation, err := mutationPayload(owner)
		if err != nil {
			return nil, err
		}
		prior := entry
		_, err = store.CommitHostMutationVerified(ctx, epoch, authority.MutationRuntimeOwner,
			runtimeOwnerKey(c.cell, claim.Environment, claim.Role), operation, entry.Sequence, wire, func(check context.Context) error {
				_, current, err := c.readRuntimeOwner(check, claim.Environment, claim.Role)
				if err != nil || current.Sequence != prior.Sequence || !bytes.Equal(current.Payload, prior.Payload) {
					return errors.Join(err, errors.New("native owner fence changed before completion"))
				}
				fresh, err := c.ownerStopped(check, owner)
				if err != nil {
					return err
				}
				for i, report := range fresh {
					if !sameReportMeaning(report, stopped[i]) || report.ObservedAt.Before(stopped[i].ObservedAt) || time.Since(stopped[i].ObservedAt) >= ReportMaxAge {
						return errors.New("native stopped receipt changed before completion")
					}
				}
				return authorized(check)
			})
		if err != nil {
			return nil, err
		}
		owner, entry, err = c.readRuntimeOwner(ctx, claim.Environment, claim.Role)
		if err != nil {
			return nil, err
		}
	}
	completed := entry
	check := func(ctx context.Context) error {
		if err := authorized(ctx); err != nil {
			return err
		}
		_, current, err := c.readRuntimeOwner(ctx, claim.Environment, claim.Role)
		if err != nil || current.Sequence != completed.Sequence || !bytes.Equal(current.Payload, completed.Payload) {
			return errors.Join(err, errors.New("completed native ownership proof changed"))
		}
		if err := c.GuardContainerOwner(ctx, claim.Environment, claim.Role); err != nil {
			return err
		}
		return authorized(ctx)
	}
	return check, check(ctx)
}
