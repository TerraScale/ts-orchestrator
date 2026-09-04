// Verifier panics become typed failures so caller-supplied implementations fail
// closed. Fatal runtime failures still terminate the process.
package protocol

// protocolExceptionPolicy recovers ordinary verifier panics.
var protocolExceptionPolicy protocolExceptionPolicyStatic

type protocolExceptionPolicyStatic struct{}

// recoverVerifierFailure runs invoke and reports whether it panicked; a panic
// is treated as an ordinary (non-fatal) verifier failure.
func (protocolExceptionPolicyStatic) recoverVerifierFailure(invoke func()) (failed bool) {
	defer func() {
		if recover() != nil {
			failed = true
		}
	}()

	invoke()
	return false
}
