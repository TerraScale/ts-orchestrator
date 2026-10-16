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
	account, scope, err := workerBrokerAccount(admitted, accountID, accountJWT)
	if err != nil {
		return nil, WorkerBrokerIdentity{}, err
	}
	if signer == nil {
		return fail("regional signing authority required")
	}
	signerID, err := signer.PublicKey()
	if err != nil || !nkeys.IsValidPublicAccountKey(signerID) {
		return fail("invalid regional account signer")
	}
	if !workerBrokerSigner(account, signerID) {
		return fail("worker requires the account key or a registered unscoped signer")
	}
	var user nkeys.KeyPair
	if len(existing) != 0 {
		user, _, err = workerBrokerUser(account, scope, existing)
		if err != nil {
			return nil, WorkerBrokerIdentity{}, err
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

// VerifyWorkerCredentials checks existing worker material without any signing
// authority. The caller verifies the account JWT's regional operator/generation.
// It never creates or renews credentials, including when existing ones expired.
func VerifyWorkerCredentials(admitted release.VerifiedFunction, accountID, accountJWT string, existing []byte) (WorkerBrokerIdentity, error) {
	account, scope, err := workerBrokerAccount(admitted, accountID, accountJWT)
	if err != nil {
		return WorkerBrokerIdentity{}, err
	}
	user, claims, err := workerBrokerUser(account, scope, existing)
	if err != nil {
		return WorkerBrokerIdentity{}, err
	}
	defer user.Wipe()
	validation := jwt.CreateValidationResults()
	claims.Validate(validation)
	if validation.IsBlocking(true) || account.IsClaimRevoked(claims) || claims.Expires <= time.Now().Unix() || !admitted.Valid() || claims.Expires > admitted.ExpiresAt().Unix() ||
		account.Expires != 0 && claims.Expires > account.Expires {
		return WorkerBrokerIdentity{}, fmt.Errorf("%w: worker credentials expired or exceed current authority", ErrScope)
	}
	inbox, _ := WorkerInboxPrefix(claims.Subject)
	return WorkerBrokerIdentity{UserNKey: claims.Subject, AccountNKey: accountID, InboxPrefix: inbox, ExpiresAt: time.Unix(claims.Expires, 0)}, nil
}

func workerBrokerAccount(admitted release.VerifiedFunction, accountID, accountJWT string) (*jwt.AccountClaims, QueueScope, error) {
	if !admitted.Valid() || !nkeys.IsValidPublicAccountKey(accountID) {
		return nil, QueueScope{}, fmt.Errorf("%w: current release and regional account required", ErrScope)
	}
	account, err := jwt.DecodeAccountClaims(accountJWT)
	if err != nil || account.Subject != accountID {
		return nil, QueueScope{}, fmt.Errorf("%w: regional account claim mismatch", ErrScope)
	}
	validation := jwt.CreateValidationResults()
	account.Validate(validation)
	if validation.IsBlocking(true) || account.Expires != 0 && account.Expires <= time.Now().Unix() {
		return nil, QueueScope{}, fmt.Errorf("%w: regional account claim invalid or expired", ErrScope)
	}
	claim := admitted.Claim()
	scope, err := QueueIdentity(Manifest{ABI: claim.ABI, TenantID: claim.TenantID, FunctionID: claim.FunctionID,
		Revision: claim.Revision, Digest: claim.Digest, Capabilities: claim.Capabilities})
	if err != nil {
		return nil, QueueScope{}, err
	}
	return account, scope, nil
}

func workerBrokerSigner(account *jwt.AccountClaims, public string) bool {
	scope, registered := account.SigningKeys.GetScope(public)
	return public == account.Subject || registered && scope == nil
}

func workerBrokerUser(account *jwt.AccountClaims, scope QueueScope, existing []byte) (nkeys.KeyPair, *jwt.UserClaims, error) {
	fail := func() (nkeys.KeyPair, *jwt.UserClaims, error) {
		return nil, nil, fmt.Errorf("%w: worker credentials have another signer, identity or grants", ErrScope)
	}
	raw, err := jwt.ParseDecoratedJWT(existing)
	if err != nil {
		return fail()
	}
	claims, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return fail()
	}
	user, err := jwt.ParseDecoratedUserNKey(existing)
	if err != nil {
		return fail()
	}
	public, err := user.PublicKey()
	if err != nil {
		user.Wipe()
		return fail()
	}
	inbox, err := WorkerInboxPrefix(public)
	if err != nil {
		user.Wipe()
		return fail()
	}
	expected := workerBrokerClaim(public, account.Subject, inbox, scope)
	if claims.Subject != public || !workerBrokerSigner(account, claims.Issuer) || claims.IssuerAccount != account.Subject ||
		claims.Name != expected.Name || claims.Audience != "" || claims.NotBefore != 0 || len(claims.Tags) != 0 ||
		claims.Expires <= claims.IssuedAt || claims.Expires-claims.IssuedAt > int64(time.Hour/time.Second) ||
		claims.IssuedAt > time.Now().Unix() || !reflect.DeepEqual(claims.UserPermissionLimits, expected.UserPermissionLimits) {
		user.Wipe()
		return fail()
	}
	return user, claims, nil
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
