package functions

import (
	"fmt"
	"reflect"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// WorkerBrokerIdentity contains only public connection metadata. Credentials
// stay in the host process; neither credentials nor signing keys enter WASM.
type WorkerBrokerIdentity struct {
	UserNKey, AccountNKey, InboxPrefix string
	ExpiresAt                          time.Time
}

// WorkerInboxPrefix is the private reply prefix passed to nats.CustomInboxPrefix.
func WorkerInboxPrefix(userNKey string) (string, error) {
	if !nkeys.IsValidPublicUserKey(userNKey) {
		return "", fmt.Errorf("%w: invalid worker public key", ErrScope)
	}
	return "_INBOX.TS_FUNCTION." + userNKey, nil
}

// IssueWorkerCredentials admits a worker under an already verified regional
// account JWT. The caller verifies the account's operator and generation before
// passing it here. Only the account key or a registered unscoped account signer
// can issue explicit worker grants; host/controller role scopes cannot.
// Existing exact credentials retain their user key across restarts and renewal.
func IssueWorkerCredentials(admitted release.VerifiedFunction, accountID, accountJWT string, signer nkeys.KeyPair, existing []byte) ([]byte, WorkerBrokerIdentity, error) {
	fail := func(reason string) ([]byte, WorkerBrokerIdentity, error) {
		return nil, WorkerBrokerIdentity{}, fmt.Errorf("%w: %s", ErrScope, reason)
	}
	if !admitted.Valid() || signer == nil || !nkeys.IsValidPublicAccountKey(accountID) {
		return fail("current release and regional signing authority required")
	}
	account, err := jwt.DecodeAccountClaims(accountJWT)
	if err != nil || account.Subject != accountID {
		return fail("regional account claim mismatch")
	}
	validation := jwt.CreateValidationResults()
	account.Validate(validation)
	if validation.IsBlocking(true) {
		return fail("regional account claim invalid or expired")
	}
	signerID, err := signer.PublicKey()
	if err != nil || !nkeys.IsValidPublicAccountKey(signerID) {
		return fail("invalid regional account signer")
	}
	authorized := func(public string) bool {
		scope, registered := account.SigningKeys.GetScope(public)
		return public == accountID || registered && scope == nil
	}
	if !authorized(signerID) {
		return fail("worker requires the account key or a registered unscoped signer")
	}
	claim := admitted.Claim()
	scope, err := QueueIdentity(Manifest{ABI: claim.ABI, TenantID: claim.TenantID, FunctionID: claim.FunctionID,
		Revision: claim.Revision, Digest: claim.Digest, Capabilities: claim.Capabilities})
	if err != nil {
		return fail("invalid function broker scope")
	}
	var user nkeys.KeyPair
	var previous *jwt.UserClaims
	if len(existing) != 0 {
		raw, err := jwt.ParseDecoratedJWT(existing)
		if err != nil {
			return fail("invalid existing worker credentials")
		}
		previous, err = jwt.DecodeUserClaims(raw)
		if err != nil {
			return fail("invalid existing worker JWT")
		}
		user, err = jwt.ParseDecoratedUserNKey(existing)
		if err != nil {
			return fail("invalid existing worker key")
		}
	} else {
		user, err = nkeys.CreateUser()
		if err != nil {
			return fail("create worker key")
		}
	}
	defer user.Wipe()
	public, err := user.PublicKey()
	if err != nil {
		return fail("read worker public key")
	}
	inbox, err := WorkerInboxPrefix(public)
	if err != nil {
		return fail("invalid worker identity")
	}
	claims := workerBrokerClaim(public, accountID, inbox, scope)
	if previous != nil {
		if previous.Subject != public || !authorized(previous.Issuer) || previous.IssuerAccount != accountID ||
			previous.Name != claims.Name || previous.Audience != "" || previous.NotBefore != 0 || len(previous.Tags) != 0 ||
			previous.Expires <= previous.IssuedAt || previous.Expires-previous.IssuedAt > int64(time.Hour/time.Second) ||
			previous.IssuedAt > time.Now().Unix() || !reflect.DeepEqual(previous.UserPermissionLimits, claims.UserPermissionLimits) {
			return fail("existing worker credentials have another signer, identity or grants")
		}
	}
	expires := min(admitted.ExpiresAt().Unix(), time.Now().Add(time.Hour).Unix())
	if account.Expires != 0 {
		expires = min(expires, account.Expires)
	}
	if !admitted.Valid() || expires <= time.Now().Unix() {
		return fail("worker authority expired during issuance")
	}
	claims.Expires = expires
	raw, err := claims.Encode(signer)
	if err != nil {
		return fail("sign worker JWT")
	}
	seed, err := user.Seed()
	if err != nil {
		return fail("read worker key")
	}
	defer clear(seed)
	creds, err := jwt.FormatUserConfig(raw, seed)
	if err != nil {
		return fail("format worker credentials")
	}
	return creds, WorkerBrokerIdentity{UserNKey: public, AccountNKey: accountID, InboxPrefix: inbox, ExpiresAt: time.Unix(expires, 0)}, nil
}

func workerBrokerClaim(public, account, inbox string, scope QueueScope) *jwt.UserClaims {
	claim := jwt.NewUserClaims(public)
	// JWT omits the library's empty CIDR slice; compare its decoded form on renewal.
	claim.Src = nil
	claim.Name, claim.IssuerAccount = scope.Subject, account
	claim.AllowedConnectionTypes = jwt.StringList{jwt.ConnectionTypeStandard}
	claim.Pub.Allow = jwt.StringList{
		"$JS.API.STREAM.INFO." + scope.Stream,
		"$JS.API.STREAM.INFO.KV_" + scope.ReceiptBucket,
		"$JS.API.CONSUMER.INFO." + scope.Stream + ".worker",
		"$JS.API.CONSUMER.MSG.NEXT." + scope.Stream + ".worker",
		"$JS.API.DIRECT.GET.KV_" + scope.ReceiptBucket + ".$KV." + scope.ReceiptBucket + ".*",
		"$KV." + scope.ReceiptBucket + ".*",
		"$JS.ACK." + scope.Stream + ".worker.*.*.*.*.*",
		"$JS.ACK.*.*." + scope.Stream + ".worker.*.*.*.*.*",
	}
	claim.Sub.Allow = jwt.StringList{inbox + ".>"}
	return claim
}
