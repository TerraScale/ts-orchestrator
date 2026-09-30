package authority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
)

// These fields are immutable at the point at which their proof is handed to a
// member. The authority log, rather than a host result, is the relay source.
func (record BackupOperationRecord) validateCompleteFields() error {
	barrier := len(record.BarrierEnvelope) != 0
	candidate := len(record.CandidateEnvelope) != 0
	completion := len(record.CompletionEnvelope) != 0
	receipt := len(record.PublicationReceipt) != 0
	release := len(record.CompleteRelease) != 0
	if len(record.BarrierEnvelope) > 8<<10 || len(record.CandidateEnvelope) > 8<<10 ||
		len(record.CompletionEnvelope) > 8<<10 || len(record.PublicationReceipt) > 18<<10 ||
		len(record.CompleteRelease) > 30<<10 ||
		len(record.AbortEnvelope) != 0 && record.State != "aborting" && record.State != "aborted" ||
		(candidate && !barrier) || (completion && !candidate) ||
		(receipt && !completion) || (release && !receipt) ||
		(receipt != (record.HeadGeneration != 0)) ||
		(release != (record.CompleteReleaseExpiresAtMS != 0)) ||
		record.CompleteReleaseExpiresAtMS > math.MaxInt64-30_000 {
		return errors.New("backup publication proof set is invalid")
	}
	switch record.State {
	case "accepted", "held", "uncertain":
		if barrier || candidate || completion || receipt || release {
			return errors.New("backup publication proof exists before Barrier")
		}
	case "aborting", "aborted":
		if completion || receipt || release {
			return errors.New("backup Abort follows publication")
		}
	case "barrier":
		if !barrier || completion || receipt || release {
			return errors.New("backup Barrier proof set is invalid")
		}
	case "publishing":
		if !barrier || !candidate || !completion || receipt || release {
			return errors.New("backup publishing proof set is invalid")
		}
	case "releasing", "complete":
		if !barrier || !candidate || !completion || !receipt || !release ||
			record.HeadGeneration != record.Ordinal {
			return errors.New("backup Complete proof set is invalid")
		}
	}
	allBarrier := true
	allComplete := true
	for _, member := range record.Roster {
		allBarrier = allBarrier && member.BarrierAcknowledged
		allComplete = allComplete && member.CompleteAcknowledged
		if member.BarrierAcknowledged && !barrier || member.CompleteAcknowledged && !release {
			return errors.New("backup acknowledgment lacks committed proof")
		}
	}
	if candidate && !allBarrier || completion && !allBarrier ||
		record.State == "complete" && !allComplete {
		return errors.New("backup publication lacks roster acknowledgments")
	}
	return nil
}

func validateBackupCompleteTransition(prior, next BackupOperationRecord) error {
	for _, pair := range [][2][]byte{
		{prior.BarrierEnvelope, next.BarrierEnvelope},
		{prior.CandidateEnvelope, next.CandidateEnvelope},
		{prior.CompletionEnvelope, next.CompletionEnvelope},
		{prior.PublicationReceipt, next.PublicationReceipt},
	} {
		if len(pair[0]) != 0 && !bytes.Equal(pair[0], pair[1]) {
			return ErrInvalidTransition
		}
	}
	if len(prior.CompleteRelease) != 0 && !bytes.Equal(prior.CompleteRelease, next.CompleteRelease) &&
		(prior.State != "releasing" || next.State != "releasing" ||
			next.CompleteReleaseExpiresAtMS <= prior.CompleteReleaseExpiresAtMS) {
		return ErrInvalidTransition
	}
	if len(prior.CompleteRelease) != 0 && bytes.Equal(prior.CompleteRelease, next.CompleteRelease) &&
		prior.CompleteReleaseExpiresAtMS != next.CompleteReleaseExpiresAtMS {
		return ErrInvalidTransition
	}
	if !bytes.Equal(prior.CompleteRelease, next.CompleteRelease) {
		for index := range prior.Roster {
			if prior.Roster[index].CompleteAcknowledged != next.Roster[index].CompleteAcknowledged {
				return ErrInvalidTransition
			}
		}
	}
	if prior.HeadGeneration != 0 && prior.HeadGeneration != next.HeadGeneration ||
		len(prior.BarrierEnvelope) == 0 && len(next.CandidateEnvelope) != 0 ||
		len(prior.CandidateEnvelope) == 0 && len(next.CompletionEnvelope) != 0 ||
		len(prior.CompletionEnvelope) == 0 && len(next.PublicationReceipt) != 0 ||
		len(prior.PublicationReceipt) == 0 && len(next.CompleteRelease) != 0 &&
			len(next.PublicationReceipt) == 0 {
		return ErrInvalidTransition
	}
	if len(next.BarrierEnvelope) != 0 && len(prior.BarrierEnvelope) == 0 && prior.State != "held" ||
		len(next.CandidateEnvelope) != 0 && len(prior.CandidateEnvelope) == 0 &&
			(prior.State != "barrier" || !allBackupBarrierAcknowledged(prior.Roster)) ||
		len(next.CompletionEnvelope) != 0 && len(prior.CompletionEnvelope) == 0 && prior.State != "barrier" ||
		len(next.PublicationReceipt) != 0 && len(prior.PublicationReceipt) == 0 && prior.State != "publishing" {
		return ErrInvalidTransition
	}
	for index, member := range next.Roster {
		old := prior.Roster[index]
		if member.BarrierAcknowledged && !old.BarrierAcknowledged && prior.State != "barrier" ||
			member.CompleteAcknowledged && !old.CompleteAcknowledged && prior.State != "releasing" ||
			len(member.CutEnvelope) != 0 && len(old.CutEnvelope) == 0 && prior.State != "accepted" {
			return ErrInvalidTransition
		}
		if len(member.CutLeafDER) != 0 {
			digest := sha256.Sum256(member.CutLeafDER)
			if hex.EncodeToString(digest[:]) != member.TLSLeafSHA256 {
				return ErrInvalidTransition
			}
		}
	}
	return nil
}

func allBackupBarrierAcknowledged(roster []BackupOperationMember) bool {
	for _, member := range roster {
		if !member.BarrierAcknowledged {
			return false
		}
	}
	return true
}
