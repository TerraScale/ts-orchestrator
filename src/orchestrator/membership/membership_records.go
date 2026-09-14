package membership

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RegionalRuntimeMembershipIdentity mirrors the C# class: a controller's
// membership signing identity — one P-256 key pair. The private key never
// leaves the process: only the key identifier, the public key, and the
// signature travel in the record.
type RegionalRuntimeMembershipIdentity struct {
	mu         sync.RWMutex
	privateKey *ecdsa.PrivateKey
	disposed   bool
	KeyId      string
	PublicKey  string
}

// RegionalRuntimeMembershipIdentityCreate mirrors the C# Create.
func RegionalRuntimeMembershipIdentityCreate() (*RegionalRuntimeMembershipIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return newRegionalRuntimeMembershipIdentity(key)
}

func newRegionalRuntimeMembershipIdentity(key *ecdsa.PrivateKey) (*RegionalRuntimeMembershipIdentity, error) {
	if key == nil {
		return nil, fmt.Errorf("membership identity key is nil")
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256(publicKey)
	return &RegionalRuntimeMembershipIdentity{
		privateKey: key,
		KeyId:      hex.EncodeToString(digest[:])[:32],
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey),
	}, nil
}

// Sign mirrors the C# Sign: signs the record's canonical material; the
// signature covers every field except itself.
func (i *RegionalRuntimeMembershipIdentity) Sign(member RegionalRuntimeMember) string {
	if i == nil {
		return ""
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.disposed || i.privateKey == nil {
		return ""
	}
	digest := sha256.Sum256([]byte(member.CanonicalMaterial()))
	signature, err := ecdsa.SignASN1(rand.Reader, i.privateKey, digest[:])
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(signature)
}

// Dispose invalidates the private key before releasing the identity. The
// explicit zeroing is best-effort (big.Int may retain implementation details),
// but it prevents future signing and bounds the key's usable lifetime.
func (i *RegionalRuntimeMembershipIdentity) Dispose() {
	if i == nil {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.disposed {
		return
	}
	i.disposed = true
	if i.privateKey != nil && i.privateKey.D != nil {
		i.privateKey.D.SetInt64(0)
	}
	i.privateKey = nil
}

// RegionalRuntimeMembershipIdentityVerify mirrors the static Verify: the key
// identifier must be the fingerprint of the embedded public key and the
// signature must verify under it.
func RegionalRuntimeMembershipIdentityVerify(member RegionalRuntimeMember) bool {
	if !member.HasWellFormedIdentityMaterial() {
		return false
	}

	publicKey, err := base64.StdEncoding.DecodeString(member.IdentityPublicKey)
	if err != nil {
		return false
	}

	digest := sha256.Sum256(publicKey)
	if hex.EncodeToString(digest[:])[:32] != member.IdentityKeyId {
		return false
	}

	parsed, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return false
	}

	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	signature, err := base64.StdEncoding.DecodeString(member.IdentitySignature)
	if err != nil {
		return false
	}

	material := sha256.Sum256([]byte(member.CanonicalMaterial()))
	return ecdsa.VerifyASN1(key, material[:], signature)
}

// RegionalRuntimeMembershipRecordClass mirrors the C# enum: the reader
// taxonomy for regional membership records.
type RegionalRuntimeMembershipRecordClass int

const (
	RegionalRuntimeMembershipRecordClassUnspecified        RegionalRuntimeMembershipRecordClass = 0
	RegionalRuntimeMembershipRecordClassHealthy            RegionalRuntimeMembershipRecordClass = 1
	RegionalRuntimeMembershipRecordClassStale              RegionalRuntimeMembershipRecordClass = 2
	RegionalRuntimeMembershipRecordClassMissing            RegionalRuntimeMembershipRecordClass = 3
	RegionalRuntimeMembershipRecordClassUnexpected         RegionalRuntimeMembershipRecordClass = 4
	RegionalRuntimeMembershipRecordClassWrongCell          RegionalRuntimeMembershipRecordClass = 5
	RegionalRuntimeMembershipRecordClassConflictingSession RegionalRuntimeMembershipRecordClass = 6
	RegionalRuntimeMembershipRecordClassStaleEpoch         RegionalRuntimeMembershipRecordClass = 7
	RegionalRuntimeMembershipRecordClassInvalidSignature   RegionalRuntimeMembershipRecordClass = 8
	RegionalRuntimeMembershipRecordClassMalformed          RegionalRuntimeMembershipRecordClass = 9
)

func (c RegionalRuntimeMembershipRecordClass) String() string {
	switch c {
	case RegionalRuntimeMembershipRecordClassUnspecified:
		return "Unspecified"
	case RegionalRuntimeMembershipRecordClassHealthy:
		return "Healthy"
	case RegionalRuntimeMembershipRecordClassStale:
		return "Stale"
	case RegionalRuntimeMembershipRecordClassMissing:
		return "Missing"
	case RegionalRuntimeMembershipRecordClassUnexpected:
		return "Unexpected"
	case RegionalRuntimeMembershipRecordClassWrongCell:
		return "WrongCell"
	case RegionalRuntimeMembershipRecordClassConflictingSession:
		return "ConflictingSession"
	case RegionalRuntimeMembershipRecordClassStaleEpoch:
		return "StaleEpoch"
	case RegionalRuntimeMembershipRecordClassInvalidSignature:
		return "InvalidSignature"
	case RegionalRuntimeMembershipRecordClassMalformed:
		return "Malformed"
	default:
		return strconv.Itoa(int(c))
	}
}

// RegionalRuntimeMembershipReader mirrors the C# static class: pure
// membership-record classification with fixed precedence.
var RegionalRuntimeMembershipReader regionalRuntimeMembershipReader

type regionalRuntimeMembershipReader struct{}

// Classify mirrors RegionalRuntimeMembershipReader.Classify.
func (regionalRuntimeMembershipReader) Classify(
	expectedCell string,
	instance string,
	expectedInstances map[string]struct{},
	previous *RegionalRuntimeMember,
	record *RegionalRuntimeMember,
	now time.Time,
) RegionalRuntimeMembershipRecordClass {
	if strings.TrimSpace(expectedCell) == "" {
		panic("The value cannot be an empty string or composed entirely of whitespace. (Parameter 'expectedCell')")
	}

	if strings.TrimSpace(instance) == "" {
		panic("The value cannot be an empty string or composed entirely of whitespace. (Parameter 'instance')")
	}

	if record == nil {
		return RegionalRuntimeMembershipRecordClassMissing
	}

	if record.Cell != expectedCell || record.Instance != instance {
		return RegionalRuntimeMembershipRecordClassWrongCell
	}

	if !record.IsValidFor(expectedCell, now) {
		return RegionalRuntimeMembershipRecordClassMalformed
	}

	if !RegionalRuntimeMembershipIdentityVerify(*record) {
		return RegionalRuntimeMembershipRecordClassInvalidSignature
	}

	// Key continuity under a live lease: a different signing key may not
	// replace the observed one while it still holds the slot. After the lease
	// lapses, healing may rotate the key with the takeover.
	if previous != nil &&
		previous.HasWellFormedIdentityMaterial() &&
		previous.IdentityPublicKey != record.IdentityPublicKey &&
		previous.LeaseExpiresAt.After(now) {
		return RegionalRuntimeMembershipRecordClassInvalidSignature
	}

	if previous != nil && record.AuthorityEpoch < previous.AuthorityEpoch {
		return RegionalRuntimeMembershipRecordClassStaleEpoch
	}

	if previous != nil &&
		previous.LeaseExpiresAt.After(now) &&
		previous.SessionId != record.SessionId {
		return RegionalRuntimeMembershipRecordClassConflictingSession
	}

	if expectedInstances != nil {
		if _, contains := expectedInstances[instance]; !contains {
			return RegionalRuntimeMembershipRecordClassUnexpected
		}
	}

	if record.LeaseExpiresAt.After(now) {
		return RegionalRuntimeMembershipRecordClassHealthy
	}

	return RegionalRuntimeMembershipRecordClassStale
}

// ExpectedInstances mirrors the C# ExpectedInstances: the expected instance
// ids of a symmetric controller set.
func (regionalRuntimeMembershipReader) ExpectedInstances(expectedControllers int) map[string]struct{} {
	switch expectedControllers {
	case 1, 3, 5:
	default:
		panic(fmt.Sprintf(
			"Specified argument was out of the range of valid values. (Parameter 'expectedControllers')\nActual value was %d.",
			expectedControllers))
	}

	instances := map[string]struct{}{}
	for index := 1; index <= expectedControllers; index++ {
		instances["controller-"+strconv.Itoa(index)] = struct{}{}
	}

	return instances
}

// RegionalRuntimeMembershipMutationClass mirrors the C# enum.
type RegionalRuntimeMembershipMutationClass int

const (
	RegionalRuntimeMembershipMutationClassUnspecified             RegionalRuntimeMembershipMutationClass = 0
	RegionalRuntimeMembershipMutationClassCreateOwnRecord         RegionalRuntimeMembershipMutationClass = 1
	RegionalRuntimeMembershipMutationClassRenewOwnRecord          RegionalRuntimeMembershipMutationClass = 2
	RegionalRuntimeMembershipMutationClassTakeOverExpiredLease    RegionalRuntimeMembershipMutationClass = 3
	RegionalRuntimeMembershipMutationClassHoldForLiveForeignLease RegionalRuntimeMembershipMutationClass = 4
	RegionalRuntimeMembershipMutationClassRejectStaleEpoch        RegionalRuntimeMembershipMutationClass = 5
	RegionalRuntimeMembershipMutationClassRejectWrongBinding      RegionalRuntimeMembershipMutationClass = 6
)

func (c RegionalRuntimeMembershipMutationClass) String() string {
	switch c {
	case RegionalRuntimeMembershipMutationClassUnspecified:
		return "Unspecified"
	case RegionalRuntimeMembershipMutationClassCreateOwnRecord:
		return "CreateOwnRecord"
	case RegionalRuntimeMembershipMutationClassRenewOwnRecord:
		return "RenewOwnRecord"
	case RegionalRuntimeMembershipMutationClassTakeOverExpiredLease:
		return "TakeOverExpiredLease"
	case RegionalRuntimeMembershipMutationClassHoldForLiveForeignLease:
		return "HoldForLiveForeignLease"
	case RegionalRuntimeMembershipMutationClassRejectStaleEpoch:
		return "RejectStaleEpoch"
	case RegionalRuntimeMembershipMutationClassRejectWrongBinding:
		return "RejectWrongBinding"
	default:
		return strconv.Itoa(int(c))
	}
}

// RegionalRuntimeMembershipMutation mirrors the C# static class: the pure
// compare-and-swap mutation policy.
var RegionalRuntimeMembershipMutation regionalRuntimeMembershipMutation

type regionalRuntimeMembershipMutation struct{}

// Decide mirrors RegionalRuntimeMembershipMutation.Decide.
func (regionalRuntimeMembershipMutation) Decide(
	boundCell string,
	boundInstance string,
	proposed RegionalRuntimeMember,
	existing *RegionalRuntimeMember,
	now time.Time,
) RegionalRuntimeMembershipMutationClass {
	if !proposed.HasWellFormedIdentityMaterial() {
		return RegionalRuntimeMembershipMutationClassRejectWrongBinding
	}

	if proposed.Cell != boundCell || proposed.Instance != boundInstance {
		return RegionalRuntimeMembershipMutationClassRejectWrongBinding
	}

	if existing == nil {
		return RegionalRuntimeMembershipMutationClassCreateOwnRecord
	}

	if existing.Cell != boundCell ||
		existing.Cluster != proposed.Cluster ||
		existing.Instance != boundInstance {
		return RegionalRuntimeMembershipMutationClassRejectWrongBinding
	}

	// The same session must keep its signing key: a session's records are
	// identity-continuous. A different session may rotate the key only with
	// the expired-lease takeover below.
	if existing.SessionId == proposed.SessionId &&
		existing.HasWellFormedIdentityMaterial() &&
		existing.IdentityPublicKey != proposed.IdentityPublicKey {
		return RegionalRuntimeMembershipMutationClassRejectWrongBinding
	}

	if existing.SessionId != proposed.SessionId {
		if existing.LeaseExpiresAt.After(now) {
			return RegionalRuntimeMembershipMutationClassHoldForLiveForeignLease
		}

		return RegionalRuntimeMembershipMutationClassTakeOverExpiredLease
	}

	if proposed.AuthorityEpoch < existing.AuthorityEpoch {
		return RegionalRuntimeMembershipMutationClassRejectStaleEpoch
	}

	if proposed.AuthorityEpoch == existing.AuthorityEpoch &&
		proposed.AuthorityRevision < existing.AuthorityRevision {
		return RegionalRuntimeMembershipMutationClassRejectStaleEpoch
	}

	if existing.LeaseExpiresAt.After(now) {
		return RegionalRuntimeMembershipMutationClassRenewOwnRecord
	}

	return RegionalRuntimeMembershipMutationClassTakeOverExpiredLease
}

// MayDeleteCurrentRecord mirrors the C# deletion rule: a publisher may delete
// only its own session's record under its own compare-and-swap revision.
func (regionalRuntimeMembershipMutation) MayDeleteCurrentRecord(
	boundSessionId string,
	current *RegionalRuntimeMember,
	heldRevision uint64,
) bool {
	return current != nil && current.SessionId == boundSessionId && heldRevision != 0
}
