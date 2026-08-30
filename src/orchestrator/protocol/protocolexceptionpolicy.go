// Port of src/TerraScale.Orchestrator/Protocol/ProtocolExceptionPolicy.cs.
//
// The C# policy distinguishes fatal runtime failures (OutOfMemoryException,
// StackOverflowException, AccessViolationException) from ordinary exceptions:
// ordinary verifier and iterator failures are swallowed into typed rejections
// while fatal ones propagate. Go has no equivalent taxonomy — the runtime
// already aborts the process on out-of-memory and stack exhaustion — so the
// policy maps onto recover(): verifier implementations that panic are treated
// as ordinary failures (fail closed with the typed verification error) and
// anything genuinely fatal kills the process, which is exactly the C#
// observable behavior.
package protocol

// protocolExceptionPolicy mirrors the internal static class.
var protocolExceptionPolicy protocolExceptionPolicyStatic

type protocolExceptionPolicyStatic struct{}

// recoverVerifierFailure runs invoke and reports whether it panicked; a panic
// stands in for the C# ordinary (non-fatal) exception path.
func (protocolExceptionPolicyStatic) recoverVerifierFailure(invoke func()) (failed bool) {
	defer func() {
		if recover() != nil {
			failed = true
		}
	}()

	invoke()
	return false
}
