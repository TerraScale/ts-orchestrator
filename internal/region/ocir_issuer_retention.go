package region

import (
	"errors"
	"reflect"
	"slices"
)

// Every own-cell writer shares this boundary: omitting an issuer sibling must
// never turn a retained or uncertain operation into a fresh first issuance.
func (r FoundationRecord) retainOCIRIssuances(next FoundationRecord) error {
	denied := errors.New("protected OCIR issuance origin, positive receipt or uncertain history cannot be removed or rewritten")
	for key, old := range r.OCIRIssuances {
		actual, ok := next.OCIRIssuances[key]
		if !ok || actual.Revision < old.Revision || actual.Origin != old.Origin || actual.State.ScopeHash != old.State.ScopeHash || actual.State.OperationID != old.State.OperationID || actual.State.Generation < old.State.Generation || actual.State.Generation == old.State.Generation && actual.State.GrantDigest != old.State.GrantDigest || actual.Revision == old.Revision && !reflect.DeepEqual(actual.State, old.State) {
			return denied
		}
		for _, pair := range [][2]string{{old.State.UserID, actual.State.UserID}, {old.State.RepositoryID, actual.State.RepositoryID}, {old.State.GroupID, actual.State.GroupID}, {old.State.PolicyID, actual.State.PolicyID}, {old.State.MembershipID, actual.State.MembershipID}, {old.State.SecretID, actual.State.SecretID}} {
			if pair[0] != "" && pair[0] != pair[1] {
				return denied
			}
		}
		for operation, original := range old.Attempts {
			current, ok := actual.Attempts[operation]
			if !ok || current.OperationID != original.OperationID || current.GrantSHA256 != original.GrantSHA256 || current.Generation != original.Generation || current.FoundationOperation != original.FoundationOperation || current.Epoch != original.Epoch || current.LeaseID != original.LeaseID || !current.LeaseUntil.Equal(original.LeaseUntil) || !current.ExpiresAt.Equal(original.ExpiresAt) || current.TokenOperation != original.TokenOperation || !current.TokenStarted.Equal(original.TokenStarted) || !slices.Equal(current.BeforeTokens, original.BeforeTokens) || current.RequestSHA256 != original.RequestSHA256 || current.VaultID != original.VaultID || current.SecretName != original.SecretName {
				return denied
			}
			for _, pair := range [][2]string{{original.TokenID, current.TokenID}, {original.PendingHash, current.PendingHash}, {original.SecretID, current.SecretID}, {original.Hash, current.Hash}} {
				if pair[0] != "" && pair[0] != pair[1] {
					return denied
				}
			}
			if original.Version != 0 && original.Version != current.Version || !original.PublishedAt.IsZero() && !original.PublishedAt.Equal(current.PublishedAt) || !original.RetiredAt.IsZero() && !original.RetiredAt.Equal(current.RetiredAt) {
				return denied
			}
		}
		for hash, original := range old.Requests {
			current, ok := actual.Requests[hash]
			if !ok || len(current.Dispatches) < len(original.Dispatches) {
				return denied
			}
			before, after := original, current
			before.Dispatches, after.Dispatches = nil, nil
			if !reflect.DeepEqual(before, after) {
				return denied
			}
			for i, dispatch := range original.Dispatches {
				observed := current.Dispatches[i]
				if !dispatch.StartedAt.Equal(observed.StartedAt) || !dispatch.FinishedAt.IsZero() && dispatch != observed {
					return denied
				}
			}
		}
	}
	return nil
}
