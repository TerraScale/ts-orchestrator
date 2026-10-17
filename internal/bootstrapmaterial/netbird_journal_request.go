package bootstrapmaterial

import (
	"crypto/ed25519"
	"time"

	"github.com/nats-io/nkeys"
)

// VerifyNetBirdJournalRequest authenticates public claims and proof of possession
// over the exact action bytes. Source, CURRENT and effect custody remain separate.
func VerifyNetBirdJournalRequest(raw, account, signer string, binding NetBirdJournalCredentialBinding, deadline, now time.Time, signingBytes, signature []byte) (NetBirdJournalCredential, error) {
	if len(signingBytes) == 0 || len(signingBytes) > 96<<10 || len(signature) != ed25519.SignatureSize {
		return NetBirdJournalCredential{}, ErrMaterial
	}
	credential, err := VerifyNetBirdJournalCredential(raw, account, signer, binding, deadline, now)
	if err != nil {
		return NetBirdJournalCredential{}, err
	}
	public, err := nkeys.FromPublicKey(credential.Subject)
	if err != nil || public.Verify(signingBytes, signature) != nil {
		return NetBirdJournalCredential{}, ErrMaterial
	}
	return credential, nil
}
