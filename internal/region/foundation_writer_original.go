package region

import "encoding/json/v2"

// Independent capability journals retain their own monotonic checkpoints;
// installing one must preserve every original launch and Policy field.
func sameFoundationWriterOriginal(before, after *FoundationWriterRecord) bool {
	if before == nil || after == nil {
		return before == nil && after == nil
	}
	original := func(writer *FoundationWriterRecord) FoundationWriterRecord {
		return FoundationWriterRecord{
			Cell: writer.Cell, Slot: writer.Slot, InstallationID: writer.InstallationID,
			GrantSHA256: writer.GrantSHA256, Generation: writer.Generation, SlotID: writer.SlotID,
			OperationID: writer.OperationID, ProfileSHA256: writer.ProfileSHA256, RecipeSHA256: writer.RecipeSHA256,
			BindingSHA256: writer.BindingSHA256, ScopeSHA256: writer.ScopeSHA256, PhysicalScopeSHA256: writer.PhysicalScopeSHA256,
			Namespace: writer.Namespace, Bucket: writer.Bucket, BucketCompartment: writer.BucketCompartment, KMSKeyID: writer.KMSKeyID,
			Request: writer.Request, RequestDigest: writer.RequestDigest, RetryToken: writer.RetryToken, FirstAttemptAt: writer.FirstAttemptAt,
			InstanceID: writer.InstanceID, Policy: writer.Policy,
		}
	}
	a, err := json.Marshal(original(before), json.Deterministic(true))
	b, nextErr := json.Marshal(original(after), json.Deterministic(true))
	return err == nil && nextErr == nil && string(a) == string(b)
}
