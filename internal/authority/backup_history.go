package authority

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"

	"github.com/nats-io/nats.go/jetstream"
)

const BackupHistoryPageLimit = 128

type BackupHistoryPage struct {
	Watermark           uint64
	NextSequence        uint64
	LatestMatchSequence uint64
	Exhausted           bool
}

// ReadBackupHistoryPage scans only one exact partition subject. The caller
// carries the pinned watermark, next sequence and latest match in its signed
// cursor; no page may turn an API failure into a not-found conclusion.
func (r *Runtime) ReadBackupHistoryPage(ctx context.Context, databaseID, partitionID,
	operationID string, watermark, next uint64,
) (BackupHistoryPage, error) {
	if r == nil || r.readStream == nil {
		return BackupHistoryPage{}, ErrFenced
	}
	key, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil || !backupUUID(operationID) {
		return BackupHistoryPage{}, ErrInvalidTransition
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	return readBackupHistoryPage(ctx, r.readStream, r.config.Scope, key,
		databaseID, partitionID, operationID, watermark, next)
}

func readBackupHistoryPage(ctx context.Context, stream jetstream.Stream, scope, key,
	databaseID, partitionID, operationID string, watermark, next uint64,
) (BackupHistoryPage, error) {
	subject := mutationSubject(scope, MutationBackupOperation, key)
	if watermark == 0 {
		last, err := stream.GetLastMsgForSubject(ctx, subject)
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			return BackupHistoryPage{Exhausted: true}, nil
		}
		if err != nil {
			return BackupHistoryPage{}, err
		}
		if last.Subject != subject || last.Sequence == 0 {
			return BackupHistoryPage{}, errors.New("backup history watermark subject is invalid")
		}
		watermark = last.Sequence
		next = 1
	}
	if next == 0 || next > watermark+1 {
		return BackupHistoryPage{}, ErrInvalidTransition
	}
	page := BackupHistoryPage{Watermark: watermark, NextSequence: next}
	for range BackupHistoryPageLimit {
		if page.NextSequence > watermark {
			page.Exhausted = true
			return page, nil
		}
		entry, err := stream.GetMsg(ctx, page.NextSequence, jetstream.WithGetMsgSubject(subject))
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			page.Exhausted = true
			return page, nil
		}
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return page, nil
			}
			return BackupHistoryPage{}, err
		}
		if entry.Subject != subject || entry.Sequence < page.NextSequence || entry.Sequence == 0 {
			return BackupHistoryPage{}, errors.New("backup history subject or sequence is invalid")
		}
		if entry.Sequence > watermark {
			page.Exhausted = true
			return page, nil
		}
		record, err := decodeBackupHistoryEntry(entry, scope, key, databaseID, partitionID)
		if err != nil {
			return BackupHistoryPage{}, err
		}
		if record.OperationID == operationID {
			page.LatestMatchSequence = entry.Sequence
		}
		page.NextSequence = entry.Sequence + 1
	}
	page.Exhausted = page.NextSequence > watermark
	return page, nil
}

func decodeBackupHistoryEntry(entry *jetstream.RawStreamMsg, scope, key,
	databaseID, partitionID string,
) (BackupOperationRecord, error) {
	if entry.Subject != mutationSubject(scope, MutationBackupOperation, key) {
		return BackupOperationRecord{}, errors.New("backup history entry subject is invalid")
	}
	outer, err := decodeControlRecord(entry.Data)
	if err != nil || outer.Scope != scope || outer.Kind != MutationBackupOperation ||
		outer.SubjectKey != key || outer.Epoch == 0 {
		return BackupOperationRecord{}, errors.New("backup history control entry is invalid")
	}
	canonical, err := json.Marshal(outer)
	if err != nil || !bytes.Equal(canonical, entry.Data) {
		return BackupOperationRecord{}, errors.New("backup history control entry is not canonical")
	}
	return decodeBackupRecord(outer.Payload, databaseID, partitionID)
}

func (r *Runtime) ReadBackupOperationAtSequence(ctx context.Context, databaseID, partitionID,
	operationID string, sequence uint64,
) (BackupOperationRecord, error) {
	if r == nil || r.readStream == nil || sequence == 0 || !backupUUID(operationID) {
		return BackupOperationRecord{}, ErrInvalidTransition
	}
	key, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return BackupOperationRecord{}, err
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	entry, err := r.readStream.GetMsg(ctx, sequence)
	if err != nil {
		return BackupOperationRecord{}, err
	}
	record, err := decodeBackupHistoryEntry(entry, r.config.Scope, key, databaseID, partitionID)
	if err != nil {
		return BackupOperationRecord{}, err
	}
	if record.OperationID != operationID {
		return BackupOperationRecord{}, ErrNotFound
	}
	return record, nil
}
