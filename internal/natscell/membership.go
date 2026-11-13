package natscell

import (
	"errors"
	"fmt"
	"slices"
)

// JetStream metadata subjects the narrowly scoped membership user may call.
// They are system-account APIs; the claim-update system user cannot use them.
const (
	MembershipServerRemoveSubject = "$JS.API.SERVER.REMOVE"
	MembershipMetaStepdownSubject = "$JS.API.META.LEADER.STEPDOWN"
)

// ValidateMembershipCredentials requires a system-account user that may only
// remove a JetStream metadata peer, step the metadata leader down and receive
// replies on its private inbox. It is used only for decommission and step-down
// and is deliberately separate from the claim-update system user.
func ValidateMembershipCredentials(path, cell, systemAccount string) error {
	if !cellName.MatchString(cell) || systemAccount == "" {
		return errors.New("membership credential cell or system account is invalid")
	}
	claim, public, err := credentialUser(path)
	if err != nil {
		return fmt.Errorf("membership credentials: %w", err)
	}
	publishes := slices.Clone([]string(claim.Pub.Allow))
	slices.Sort(publishes)
	if credentialAccount(claim) != systemAccount ||
		!slices.Equal(publishes, []string{MembershipMetaStepdownSubject, MembershipServerRemoveSubject}) ||
		len(claim.Pub.Deny) != 0 || len(claim.Sub.Allow) != 1 ||
		claim.Sub.Allow[0] != inboxPrefix(cell, public)+".>" || len(claim.Sub.Deny) != 0 ||
		claim.Resp != nil {
		return errors.New("membership credentials must have only server-remove, metadata step-down and private reply grants")
	}
	return nil
}
