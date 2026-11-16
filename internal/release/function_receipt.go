package release

// VerifiedFunctionReceipt proves current signed metadata, never module execution
// authority. Module bytes must independently pass VerifyFunctionCurrent.
type VerifiedFunctionReceipt struct {
	claim FunctionClaim
	proof receiptProof
}
