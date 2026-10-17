package authority

import "context"

// ReadBackupObservation keeps one validated record beside its exact committed log metadata.
func ReadBackupObservation(ctx context.Context, source interface {
	ReadHostMutation(context.Context, HostMutationKind, string) (LogEntry, error)
}, databaseID, partitionID string) (BackupOperationRecord, LogEntry, error) {
	key, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return BackupOperationRecord{}, LogEntry{}, err
	}
	entry, err := source.ReadHostMutation(ctx, MutationBackupOperation, key)
	if err != nil {
		return BackupOperationRecord{}, LogEntry{}, err
	}
	record, err := decodeBackupRecord(entry.Payload, databaseID, partitionID)
	if err != nil {
		return BackupOperationRecord{}, LogEntry{}, err
	}
	entry.Payload = nil
	return record, entry, nil
}
