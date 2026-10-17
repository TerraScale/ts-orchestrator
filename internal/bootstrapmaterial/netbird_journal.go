package bootstrapmaterial

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// NetBirdJournalCredentialBinding contains public signed identities only.
// Native underlay, CURRENT and root process custody remain separate proofs.
type NetBirdJournalCredentialBinding struct {
	PurposeSHA256, GrantSHA256, TemplateSHA256, SourceSHA256 string
	ManagerSlotID, WriterSlotID                              string
}

func (binding NetBirdJournalCredentialBinding) tags() jwt.TagList {
	return jwt.TagList{
		bootstrap.NetBirdAccountJournalPurpose,
		"purpose:" + binding.PurposeSHA256, "grant:" + binding.GrantSHA256,
		"template:" + binding.TemplateSHA256, "source:" + binding.SourceSHA256,
		"manager:" + binding.ManagerSlotID, "writer:" + binding.WriterSlotID,
	}
}

func (binding NetBirdJournalCredentialBinding) validate() error {
	for _, value := range []string{binding.PurposeSHA256, binding.GrantSHA256, binding.TemplateSHA256, binding.SourceSHA256} {
		wire, err := hex.DecodeString(value)
		if err != nil || len(wire) != sha256.Size || hex.EncodeToString(wire) != value {
			return ErrMaterial
		}
	}
	if !entityid.Valid(binding.ManagerSlotID) || !entityid.Valid(binding.WriterSlotID) || binding.ManagerSlotID == binding.WriterSlotID {
		return ErrMaterial
	}
	return nil
}

// NetBirdJournalCredential is authenticated public metadata, never authority to
// reserve, dispatch, complete, open a listener or use a private key.
type NetBirdJournalCredential struct {
	ID, Subject, SHA256 string
	IssuedAt, ExpiresAt time.Time
}

// IssueNetBirdJournalCredentials requires the same genuine original writer
// startup retained at load. It issues no NATS publish or subscribe authority.
func (issuer *ControllerIssuer) IssueNetBirdJournalCredentials(ctx context.Context, originalDeadline time.Time, purpose bootstrap.VerifiedNetBirdJournalPurpose) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || issuer == nil || issuer.signer == nil || issuer.cert == nil ||
		!issuer.startup.IsVerified() || !purpose.IsVerified() || originalDeadline.IsZero() || issuer.identity.Cell != "GRU" {
		return nil, ErrMaterial
	}
	deadline := originalDeadline
	now := time.Now()
	for _, cap := range []time.Time{purpose.ExpiresAt(), issuer.startup.ExpiresAt(), issuer.identity.expiresAt, issuer.cert.NotAfter, now.Add(issuer.lifetime() - issuedBackdate)} {
		if cap.IsZero() {
			return nil, ErrMaterial
		}
		deadline = minTime(deadline, cap)
	}
	if deadline.Unix() <= now.Unix() || issuer.lifetime() <= issuedBackdate {
		return nil, ErrMaterial
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if purpose.MatchesStartup(ctx, issuer.startup) != nil {
		return nil, ErrMaterial
	}
	signed := purpose.Purpose()
	binding := NetBirdJournalCredentialBinding{
		PurposeSHA256: purpose.Digest(), GrantSHA256: purpose.GrantDigest(), TemplateSHA256: purpose.TemplateDigest(),
		SourceSHA256: issuer.startup.SourceSHA256(), ManagerSlotID: signed.Manager.SlotID, WriterSlotID: signed.Writer.SlotID,
	}
	if binding.validate() != nil {
		return nil, ErrMaterial
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		return nil, err
	}
	defer user.Wipe()
	public, err := user.PublicKey()
	if err != nil {
		return nil, err
	}
	claim := jwt.NewUserClaims(public)
	claim.Name, claim.IssuerAccount, claim.Expires = bootstrap.NetBirdAccountJournalPurpose, issuer.identity.CellAccount, deadline.Unix()
	claim.Tags = binding.tags()
	claim.Pub.Deny, claim.Sub.Deny = jwt.StringList{">"}, jwt.StringList{">"}
	claim.AllowedConnectionTypes = jwt.StringList{jwt.ConnectionTypeInProcess}
	creds, err := credentials(claim, issuer.signer, user)
	if err != nil {
		return nil, err
	}
	raw, err := jwt.ParseDecoratedJWT(creds)
	if err == nil {
		_, err = VerifyNetBirdJournalCredential(raw, issuer.identity.CellAccount, issuer.identity.AccountSigner, binding, deadline, time.Now())
	}
	if err != nil || purpose.MatchesStartup(ctx, issuer.startup) != nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		clear(creds)
		return nil, ErrMaterial
	}
	return creds, nil
}

// VerifyNetBirdJournalCredential checks a public raw JWT against independently
// pinned inputs. It returns claims only; it cannot mint source or effect custody.
func VerifyNetBirdJournalCredential(raw, account, signer string, binding NetBirdJournalCredentialBinding, deadline, now time.Time) (NetBirdJournalCredential, error) {
	if len(raw) == 0 || len(raw) > bootstrap.MaxSecretBytes || binding.validate() != nil ||
		!nkeys.IsValidPublicAccountKey(account) || !nkeys.IsValidPublicAccountKey(signer) || account == signer ||
		deadline.IsZero() || now.IsZero() || !now.Before(deadline) {
		return NetBirdJournalCredential{}, ErrMaterial
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return NetBirdJournalCredential{}, ErrMaterial
	}
	validation := jwt.CreateValidationResults()
	claim.Validate(validation)
	if validation.IsBlocking(true) || claim.ID == "" || !nkeys.IsValidPublicUserKey(claim.Subject) || claim.Issuer != signer || claim.IssuerAccount != account ||
		claim.Name != bootstrap.NetBirdAccountJournalPurpose || claim.Audience != "" || claim.NotBefore != 0 || claim.IssuedAt <= 0 ||
		claim.Expires <= claim.IssuedAt || time.Unix(claim.IssuedAt, 0).After(now) || !now.Before(time.Unix(claim.Expires, 0)) ||
		time.Unix(claim.Expires, 0).After(deadline) || !slices.Equal(claim.Tags, binding.tags()) ||
		len(claim.Pub.Allow)+len(claim.Sub.Allow) != 0 || !slices.Equal(claim.Pub.Deny, jwt.StringList{">"}) || !slices.Equal(claim.Sub.Deny, jwt.StringList{">"}) ||
		claim.Resp != nil || claim.BearerToken || claim.ProxyRequired || len(claim.Src)+len(claim.Times) != 0 || claim.Locale != "" ||
		claim.Subs != jwt.NoLimit || claim.Data != jwt.NoLimit || claim.Payload != jwt.NoLimit ||
		!slices.Equal(claim.AllowedConnectionTypes, jwt.StringList{jwt.ConnectionTypeInProcess}) {
		return NetBirdJournalCredential{}, ErrMaterial
	}
	sum := sha256.Sum256([]byte(raw))
	return NetBirdJournalCredential{ID: claim.ID, Subject: claim.Subject, SHA256: hex.EncodeToString(sum[:]),
		IssuedAt: time.Unix(claim.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(claim.Expires, 0).UTC()}, nil
}
