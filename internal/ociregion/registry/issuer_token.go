package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func credentialHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (a *issuerAttempt) ref() vaultsecret.Ref {
	intent := a.issuer.scope.Intent()
	return vaultsecret.Ref{Vault: intent.VaultTarget.VaultID, Name: intent.SecretName}
}

func (a *issuerAttempt) tokens(ctx context.Context) ([]identity.AuthToken, error) {
	response, err := a.issuer.identity.ListAuthTokens(ociclient.RequestContext(ctx), identity.ListAuthTokensRequest{UserId: new(a.state.UserID)})
	if err != nil || response.OpcNextPage != nil || len(response.Items) > 2 {
		return nil, ErrIssuer
	}
	for _, token := range response.Items {
		if !strings.HasPrefix(text(token.Id), "ocid1.credential.") || text(token.UserId) != a.state.UserID || token.TimeCreated == nil ||
			token.LifecycleState != identity.AuthTokenLifecycleStateActive && token.LifecycleState != identity.AuthTokenLifecycleStateCreating {
			return nil, ErrIssuer
		}
	}
	return response.Items, nil
}

func (a *issuerAttempt) ensureCredential(ctx context.Context, user identity.User) error {
	if err := a.check(ctx); err != nil {
		return err
	}
	current, readErr := vaultsecret.ReadCurrent(ociclient.RequestContext(ctx), a.issuer.secrets, a.ref())
	if a.state.Stage == "vault-pending" {
		if readErr == nil && a.state.PendingHash != "" && credentialHash(current.Value()) == a.state.PendingHash &&
			(a.state.SecretID == "" || current.ID == a.state.SecretID) && current.Version > a.state.Version {
			if err := a.published(ctx, current); err != nil {
				return err
			}
		} else {
			// Bytes were lost before publication was confirmed. Revoke that exact
			// token before clearing its operation, even if Vault later converges.
			if a.state.TokenID == "" {
				return ErrIssuer
			}
			if err := a.revoke(ctx, a.state.TokenID); err != nil {
				return err
			}
			a.state.TokenID = a.state.PriorTokenID
			a.state.PriorTokenID = ""
			a.state.Stage = "ready"
			a.state.TokenOperation = ""
			a.state.PendingHash = ""
			if err := a.save(ctx, true); err != nil {
				return err
			}
			// Reread after revocation, never reuse an earlier observation.
			current, readErr = vaultsecret.ReadCurrent(ociclient.RequestContext(ctx), a.issuer.secrets, a.ref())
		}
	}
	if a.state.PriorTokenID != "" && a.state.Stage == "ready" {
		if err := a.activeToken(ctx); err != nil {
			return err
		}
		if err := a.revoke(ctx, a.state.PriorTokenID); err != nil {
			return err
		}
		a.state.PriorTokenID = ""
		if err := a.save(ctx, true); err != nil {
			return err
		}
	}
	if a.state.Stage == "ready" && a.state.Hash != "" {
		if readErr != nil || current.ID != a.state.SecretID || current.Version != a.state.Version || credentialHash(current.Value()) != a.state.Hash {
			return ErrIssuer
		}
		scope := PullScope{RegistryHost: a.issuer.host, Repository: a.issuer.scope.Intent().RegistryNamespace + "/" + a.issuer.scope.Intent().RepositoryName}
		credential, err := decodePull(current.Value(), scope)
		if err != nil || credential.username != a.issuer.scope.Intent().RegistryNamespace+"/"+text(user.Name) {
			return ErrIssuer
		}
		tokens, err := a.tokens(ctx)
		if err != nil {
			return err
		}
		valid := false
		for _, token := range tokens {
			if text(token.Id) != a.state.TokenID {
				return ErrIssuer
			}
			valid = token.LifecycleState == identity.AuthTokenLifecycleStateActive && (token.TimeExpires == nil || time.Now().Before(token.TimeExpires.Time))
		}
		if !valid {
			return ErrIssuer
		}
		if time.Since(a.state.PublishedAt) < tokenRotation {
			return nil
		}
	}
	if a.state.TokenOperation == "" {
		if readErr != nil && !vaultsecret.Absent(readErr) {
			return ErrIssuer
		}
		// An existing unrecorded Vault value cannot be adopted or overwritten.
		if readErr == nil && a.state.SecretID == "" {
			return ErrIssuer
		}
		tokens, err := a.tokens(ctx)
		if err != nil {
			return err
		}
		before := make([]string, 0, len(tokens))
		for _, token := range tokens {
			if text(token.Id) != a.state.TokenID || a.state.TokenID == "" {
				return ErrIssuer
			}
			before = append(before, text(token.Id))
		}
		a.state.BeforeTokens = before
		a.state.TokenOperation = uuid.New().String()
		a.state.TokenStarted = time.Now().UTC()
		a.state.Stage = "token-pending"
		if err := a.save(ctx, true); err != nil {
			return err
		}
	}
	if a.state.Stage != "token-pending" {
		return ErrIssuer
	}
	return a.issue(ctx, user)
}

func (a *issuerAttempt) issue(ctx context.Context, user identity.User) error {
	var token identity.AuthToken
	// Even an explicit later replay uses the durable same-operation token.
	err := a.call(ctx, true, func(ctx context.Context) error {
		response, err := a.issuer.identity.CreateAuthToken(ctx, identity.CreateAuthTokenRequest{
			UserId: new(a.state.UserID), Description: new("terrascale-ocir:" + a.state.TokenOperation), OpcRetryToken: new(a.state.TokenOperation),
			RequestMetadata: common.RequestMetadata{RetryPolicy: new(common.NoRetryPolicy())}})
		token = response.AuthToken
		return err
	})
	if err != nil || text(token.Token) == "" {
		// Exact pending operation + pre-request inventory are required before
		// revoking an observed lost-value token. Description alone is not proof.
		tokens, listErr := a.tokens(ctx)
		if listErr != nil {
			return ErrIssuer
		}
		candidate := ""
		for _, observed := range tokens {
			if slices.Contains(a.state.BeforeTokens, text(observed.Id)) {
				continue
			}
			if candidate != "" || text(observed.Description) != "terrascale-ocir:"+a.state.TokenOperation || observed.TimeCreated.Time.Before(a.state.TokenStarted.Add(-time.Second)) {
				return ErrIssuer
			}
			candidate = text(observed.Id)
		}
		if candidate == "" {
			return ErrIssuer
		}
		// Persist the exact recovered OCID before any delete or fresh issuance.
		a.state.PriorTokenID = a.state.TokenID
		a.state.TokenID = candidate
		a.state.Stage = "vault-pending"
		if err := a.save(ctx, true); err != nil {
			return err
		}
		return ErrIssuer
	}
	if !strings.HasPrefix(text(token.Id), "ocid1.credential.") || text(token.UserId) != a.state.UserID ||
		text(token.Description) != "terrascale-ocir:"+a.state.TokenOperation || token.TimeCreated == nil || token.TimeCreated.Time.Before(a.state.TokenStarted.Add(-time.Second)) ||
		slices.Contains(a.state.BeforeTokens, text(token.Id)) {
		return ErrIssuer
	}
	value, err := json.Marshal(struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{a.issuer.scope.Intent().RegistryNamespace + "/" + text(user.Name), text(token.Token)})
	if err != nil {
		return ErrIssuer
	}
	a.state.PriorTokenID = a.state.TokenID
	a.state.TokenID = text(token.Id)
	a.state.PendingHash = credentialHash(string(value))
	a.state.Stage = "vault-pending"
	if err := a.save(ctx, true); err != nil {
		return err
	}
	// Never persist value or include provider errors that may echo request bytes.
	if err := a.call(ctx, false, func(ctx context.Context) error {
		if a.state.SecretID == "" {
			_, err := vaultsecret.Ensure(ctx, a.issuer.vault, a.issuer.scope.Intent().VaultTarget, a.ref().Name, "TerraScale exact repository pull credential", func(context.Context) (string, error) { return string(value), nil })
			return err
		}
		_, err := vaultsecret.PublishVersion(ctx, a.issuer.vault, a.ref(), a.state.SecretID, a.state.Version, value)
		return err
	}); err != nil {
		return err
	}
	current, err := vaultsecret.ReadCurrent(ociclient.RequestContext(ctx), a.issuer.secrets, a.ref())
	if err != nil || credentialHash(current.Value()) != a.state.PendingHash || a.state.SecretID != "" && current.ID != a.state.SecretID || current.Version <= a.state.Version {
		return ErrIssuer
	}
	if err := a.published(ctx, current); err != nil {
		return err
	}
	if err := a.activeToken(ctx); err != nil {
		return err
	}
	if a.state.PriorTokenID != "" {
		if err := a.revoke(ctx, a.state.PriorTokenID); err != nil {
			return err
		}
		a.state.PriorTokenID = ""
		return a.save(ctx, true)
	}
	return nil
}

func (a *issuerAttempt) activeToken(ctx context.Context) error {
	tokens, err := a.tokens(ctx)
	if err != nil {
		return err
	}
	found := false
	for _, token := range tokens {
		if text(token.Id) == a.state.PriorTokenID {
			continue
		}
		if text(token.Id) != a.state.TokenID {
			return ErrIssuer
		}
		found = token.LifecycleState == identity.AuthTokenLifecycleStateActive && (token.TimeExpires == nil || time.Now().Before(token.TimeExpires.Time))
	}
	if !found {
		return ErrIssuer
	}
	return nil
}

func (a *issuerAttempt) published(ctx context.Context, current vaultsecret.Current) error {
	a.state.SecretID, a.state.Version, a.state.Hash = current.ID, current.Version, a.state.PendingHash
	a.state.PendingHash, a.state.TokenOperation = "", ""
	a.state.BeforeTokens = nil
	a.state.PublishedAt = time.Now().UTC()
	a.state.Stage = "ready"
	return a.save(ctx, true)
}

func (a *issuerAttempt) revoke(ctx context.Context, id string) error {
	tokens, err := a.tokens(ctx)
	if err != nil {
		return err
	}
	for _, token := range tokens {
		if text(token.Id) != id {
			continue
		}
		if err := a.call(ctx, true, func(ctx context.Context) error {
			_, err := a.issuer.identity.DeleteAuthToken(ctx, identity.DeleteAuthTokenRequest{UserId: new(a.state.UserID), AuthTokenId: new(id)})
			return err
		}); err != nil {
			return err
		}
	}
	tokens, err = a.tokens(ctx)
	if err != nil {
		return err
	}
	for _, token := range tokens {
		if text(token.Id) == id {
			return ErrIssuer
		}
	}
	return nil
}
