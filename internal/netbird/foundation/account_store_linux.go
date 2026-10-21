package foundation

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

type accountJournal struct {
	Binding        storeBinding `json:"binding"`
	SetupState     string       `json:"setupState"`
	OwnerID        string       `json:"ownerId,omitempty"`
	ServiceID      string       `json:"serviceId,omitempty"`
	ServiceAttempt string       `json:"serviceAttempt,omitempty"`
	TokenAttempt   string       `json:"tokenAttempt,omitempty"`
	PreviousTokens []string     `json:"previousTokens,omitempty"`
	PATID          string       `json:"patId,omitempty"`
	PAT            string       `json:"pat,omitempty"`
	PublishedPATID string       `json:"publishedPatId,omitempty"`
}

func accountID(value string) bool {
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "/\\?#% \t\r\n\x00")
}

func (j accountJournal) validate(binding storeBinding) error {
	if j.Binding != binding || !slices.Contains([]string{"unattempted", "attempted", "verified"}, j.SetupState) ||
		j.SetupState == "verified" && !accountID(j.OwnerID) || j.OwnerID != "" && !accountID(j.OwnerID) || j.ServiceID != "" && !accountID(j.ServiceID) ||
		j.ServiceID != "" && j.OwnerID == "" || j.ServiceAttempt != "" && j.ServiceAttempt != "attempted" || j.ServiceAttempt != "" && j.OwnerID == "" || j.PATID != "" && !accountID(j.PATID) || j.PublishedPATID != "" && !accountID(j.PublishedPATID) ||
		(j.PATID == "") != (j.PAT == "") || j.PAT != "" && (!netbird.ValidAdminPAT([]byte(j.PAT)) || j.ServiceID == "") ||
		j.TokenAttempt != "" && j.TokenAttempt != "attempted" || j.TokenAttempt != "" && j.ServiceID == "" || len(j.PreviousTokens) > 128 || j.TokenAttempt == "" && len(j.PreviousTokens) > 0 {
		return errors.New("NetBird account escrow differs from its retained store identity")
	}
	seen := make(map[string]bool, len(j.PreviousTokens))
	for _, id := range j.PreviousTokens {
		if !accountID(id) || seen[id] {
			return errors.New("NetBird token attempt baseline is malformed")
		}
		seen[id] = true
	}
	return nil
}

func (o *owner) loadAccount() (accountJournal, error) {
	var j accountJournal
	found, err := o.custody.loadAccount(&j)
	if err != nil {
		return j, err
	}
	if !found {
		return j, errors.New("NetBird retained account identity is missing; restore the original store")
	}
	return j, j.validate(o.custody.binding())
}

func (o *owner) saveAccount(ctx context.Context, material region.NetBirdComponents, next accountJournal) error {
	if err := o.authorize(ctx, material); err != nil {
		return err
	}
	if err := next.validate(o.custody.binding()); err != nil {
		return err
	}
	var old accountJournal
	found, err := o.custody.loadAccount(&old)
	if err != nil {
		return err
	}
	if found {
		if err = old.validate(o.custody.binding()); err != nil {
			return err
		}
		if old.OwnerID != "" && old.OwnerID != next.OwnerID || old.ServiceID != "" && old.ServiceID != next.ServiceID || old.SetupState == "verified" && next.SetupState != "verified" || old.SetupState == "attempted" && next.SetupState == "unattempted" {
			return errors.New("NetBird retained account identity cannot be replaced")
		}
		if old.PAT != "" && next.PAT != old.PAT && (next.PAT != "" || next.PublishedPATID != old.PATID) {
			return errors.New("NetBird unpublished PAT escrow cannot be replaced")
		}
	}
	return o.custody.saveAccount(next)
}
