// Verifier panics become typed failures so caller-supplied implementations fail
// closed. Fatal runtime failures still terminate the process.
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
