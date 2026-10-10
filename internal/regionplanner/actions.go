package regionplanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

// add proposes the region and approves it at once, inside the guards Decide
// checked. A cell with a terminal record gets a new generation.
func (runner *Runner) add(ctx context.Context, epoch uint64, decision Decision, monthlyCents uint64, now time.Time) error {
	digest, err := decisionDigest(decision)
	if err != nil {
		return err
	}
	prior, revision, err := runner.Lifecycle.Get(ctx, decision.Cell)
	proposal := regionlifecycle.Proposal{Cell: decision.Cell, OCIRegion: decision.OCIRegion, Reason: decision.Reason,
		EvidenceDigests: []string{digest}, EstimatedMonthlyCents: monthlyCents, ProposedAt: now.UTC()}
	var record regionlifecycle.Record
	switch {
	case errors.Is(err, regionlifecycle.ErrNotFound):
		proposal.ID = proposalID(decision, 1)
		if record, err = runner.Machine.Propose(proposal, now); err == nil {
			revision, err = runner.Lifecycle.Create(ctx, epoch, record)
		}
	case err != nil:
		return err
	default:
		proposal.ID = proposalID(decision, prior.Generation+1)
		if record, err = runner.Machine.Repropose(prior, proposal, now); err == nil {
			revision, err = runner.Lifecycle.Repropose(ctx, epoch, prior, record, revision)
		}
	}
	if err != nil {
		return fmt.Errorf("propose: %w", err)
	}
	journalProposal(ctx, epoch, record, decision)
	approved, err := runner.Machine.Approve(record, now)
	if err != nil {
		return fmt.Errorf("approve: %w", err)
	}
	if _, err := runner.Lifecycle.Update(ctx, epoch, record, approved, revision); err != nil {
		return fmt.Errorf("store approval: %w", err)
	}
	journalApproval(ctx, epoch, approved, decision)
	return nil
}

// remove proposes retiring an Active region whose idle status has held since
// idleSince, and approves it at once.
func (runner *Runner) remove(ctx context.Context, epoch uint64, decision Decision, idleSince time.Time, now time.Time) error {
	digest, err := decisionDigest(decision)
	if err != nil {
		return err
	}
	record, revision, err := runner.Lifecycle.Get(ctx, decision.Cell)
	if err != nil {
		return err
	}
	// shortcut: placement intents and members are not read yet, so the idle status is the only evidence; upgrade when the region reports both counts.
	proposed, err := runner.Machine.ProposeRetire(record, regionlifecycle.IdleEvidence{IdleSince: idleSince,
		EvidenceDigest: digest}, now)
	if err != nil {
		return fmt.Errorf("propose retirement: %w", err)
	}
	if revision, err = runner.Lifecycle.Update(ctx, epoch, record, proposed, revision); err != nil {
		return fmt.Errorf("store retirement proposal: %w", err)
	}
	journalRetirement(ctx, epoch, proposed, decision)
	approved, err := runner.Machine.ApproveRetire(proposed, now)
	if err != nil {
		return fmt.Errorf("approve retirement: %w", err)
	}
	if _, err := runner.Lifecycle.Update(ctx, epoch, proposed, approved, revision); err != nil {
		return fmt.Errorf("store retirement approval: %w", err)
	}
	journalRetirementApproval(ctx, epoch, approved, decision)
	return nil
}

// proposalID names one proposal attempt: the cell, its generation and the
// decision time, so no two attempts share an ID.
func proposalID(decision Decision, generation uint64) string {
	return entityid.Derive("region-proposal", decision.Cell, strconv.FormatUint(generation, 10),
		decision.At.UTC().Format(time.RFC3339Nano))
}

// decisionDigest is the SHA-256 of a decision's stored encoding, the evidence
// a proposal or retirement cites.
func decisionDigest(decision Decision) (string, error) {
	data, err := protocol.EncodeJSON(decision)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func journalProposal(ctx context.Context, epoch uint64, record regionlifecycle.Record, decision Decision) {
	journal(ctx, epoch, record.Cell, record.Proposal.OCIRegion, decisionlog.KindRegionProposed, decisionlog.StatusPending,
		fmt.Sprintf("Proposed region %s (%s)", record.Cell, record.Proposal.OCIRegion), decision.Reason,
		map[string]string{"proposal": record.Proposal.ID, "evidence": strings.Join(record.Proposal.EvidenceDigests, ","),
			"cents": strconv.FormatUint(record.Proposal.EstimatedMonthlyCents, 10)})
}

func journalApproval(ctx context.Context, epoch uint64, record regionlifecycle.Record, decision Decision) {
	journal(ctx, epoch, record.Cell, record.Proposal.OCIRegion, decisionlog.KindRegionApproved, decisionlog.StatusPending,
		fmt.Sprintf("Approved region %s inside the budget and region guards", record.Cell), decision.Reason,
		map[string]string{"proposal": record.Proposal.ID})
}

func journalRetirement(ctx context.Context, epoch uint64, record regionlifecycle.Record, decision Decision) {
	journal(ctx, epoch, record.Cell, record.Proposal.OCIRegion, decisionlog.KindRegionProposed, decisionlog.StatusPending,
		fmt.Sprintf("Proposed retiring region %s", record.Cell), decision.Reason,
		map[string]string{"proposal": record.Proposal.ID})
}

func journalRetirementApproval(ctx context.Context, epoch uint64, record regionlifecycle.Record, decision Decision) {
	journal(ctx, epoch, record.Cell, record.Proposal.OCIRegion, decisionlog.KindRegionApproved, decisionlog.StatusPending,
		fmt.Sprintf("Approved retiring region %s inside the idle guard", record.Cell), decision.Reason,
		map[string]string{"proposal": record.Proposal.ID})
}

func journalHold(ctx context.Context, epoch uint64, home string, decision Decision) {
	journal(ctx, epoch, home, "", decisionlog.KindHeld, decisionlog.StatusPending,
		"The region planner holds region actions", decision.Reason, nil)
}

func journal(ctx context.Context, epoch uint64, cell, ociRegion string, kind decisionlog.Kind,
	status decisionlog.Status, summary, reason string, attrs map[string]string,
) {
	decisionlog.Record(ctx, decisionlog.Decision{Region: cell, Actor: decisionlog.Actor{Slice: "regionplanner"},
		Kind: kind, Subject: decisionlog.Subject{Kind: "region", ID: cell, Name: ociRegion}, Summary: summary,
		Reason: reason, Rule: "regionplanner.decide", Status: status, Epoch: epoch, Attrs: attrs})
}
