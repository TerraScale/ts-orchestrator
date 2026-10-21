package bootstrap

import "time"

// StartupAuthority is sealed to bootstrap verification constructors. Both
// historical root-signed manifests and derived same-grant startup proofs expose
// the same checked installation facts without pretending to share a signature.
type StartupAuthority interface {
	Manifest() Manifest
	Digest() string
	StorageDomain() StorageDomain
	Profile(string) (LaunchProfile, bool)
	IssuedAt() time.Time
	ExpiresAt() time.Time
	verifyStartupAuthority() error
}

func (verified VerifiedManifest) IssuedAt() time.Time  { return verified.issuedAt }
func (verified VerifiedManifest) ExpiresAt() time.Time { return verified.expiresAt }
func (verified VerifiedManifest) verifyStartupAuthority() error {
	return validateVerifiedManifest(verified)
}

func validateStartupAuthority(authority StartupAuthority) error {
	if authority == nil {
		return ErrManifestInvalid
	}
	return authority.verifyStartupAuthority()
}
