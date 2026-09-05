package directory

// RegionalRuntimeMembershipIdentityFromPEM parses captured identity bytes.
// Admission and bounded file ownership checks belong to the caller. The
// resulting signer owns its parsed key and must be disposed by the runtime.
func RegionalRuntimeMembershipIdentityFromPEM(data []byte) (*RegionalRuntimeMembershipIdentity, error) {
	return parseMembershipIdentityPEM(data)
}
