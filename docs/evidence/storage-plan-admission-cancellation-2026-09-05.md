# Storage plan admission cancellation

The admission regression reproduced two false-success cases before the fix:
cancellation after the private pin rename, and source command expiry at that
same boundary. Both returned a verified plan with no error.

Admission now rechecks cancellation, plan lifetime, and command expiry after
directory persistence. Identical admission retries perform the same final
checks. Resume rechecks cancellation after its directory sync. The durable pin
is retained when the caller receives an error.

`TestStorageTransitionAdmissionInterruptedAfterRenamePreservesRecoverablePin`
injects both interruptions, requires an error and an empty verified result,
checks that the original source remains live, closes and reopens the receiver,
and resumes the exact retained plan under a fresh context. It compares the pin
bytes before and after recovery. Both cases failed before the change and pass
after it.

Validation logs accompany this record. This is host admission recovery evidence;
it does not qualify plan delivery, storage effects, R3 promotion, or production
runtime composition.
