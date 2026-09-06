package serviceidentityrotation

import (
	"math"
	"net/url"
	"slices"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

func validReference(r hostsecrets.IdentitySecretReference) bool {
	if r == (hostsecrets.IdentitySecretReference{}) {
		return true
	}
	if !strings.HasPrefix(r.SecretID, "ocid1.vaultsecret.") || len(r.SecretID) > 512 || r.VersionNumber != 1 || r.Generation == 0 || r.Generation >= math.MaxInt64 || len(r.OperationID) == 0 || len(r.OperationID) > 128 {
		return false
	}
	for _, c := range r.SecretID + r.OperationID {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validJournal(j Journal) bool {
	if emptyJournal(j) {
		return true
	}
	if j.RosterRevision == 0 || !validJournalRoster(j.Members) || j.Generation == 0 || j.Generation >= math.MaxInt64 || !validReference(j.Active) || !validReference(j.Pending) || j.Active.Generation > j.Generation || j.Pending.SecretID != "" && j.Pending.Generation != j.Generation {
		return false
	}
	switch j.Phase {
	case "":
		return j.Active.SecretID != "" && j.Pending == (hostsecrets.IdentitySecretReference{}) && j.Deadline.IsZero() && !j.NextRotation.IsZero()
	case "bootstrap":
		return j.Generation == 1 && j.Active == (hostsecrets.IdentitySecretReference{}) && !j.Deadline.IsZero()
	case "issue":
		return j.Active.SecretID != "" && j.Pending == (hostsecrets.IdentitySecretReference{}) && !j.Deadline.IsZero()
	case "stage", "commit":
		return j.Active.SecretID != "" && j.Pending.SecretID != "" && !j.Deadline.IsZero()
	case "rollback":
		return j.Active.SecretID != "" && !j.Deadline.IsZero()
	}
	return false
}

// Issued references and deadlines cannot be replaced during a pending operation.
func rotationIntentTransition(prior, next *Journal) error {
	if next == nil {
		return ErrStateConflict
	}
	if prior == nil || emptyJournal(*prior) {
		if next.Phase != "bootstrap" || next.Generation != 1 || next.RosterRevision != 1 {
			return ErrStateConflict
		}
		return nil
	}
	if sameJournal(*prior, *next) {
		return nil
	}
	if prior.Phase == "" && next.Phase == "" {
		if prior.RosterRevision == math.MaxUint64 || next.RosterRevision != prior.RosterRevision+1 || !validJournalRoster(next.Members) {
			return ErrStateConflict
		}
		normalized := *next
		normalized.Members = prior.Members
		normalized.RosterRevision = prior.RosterRevision
		if !sameJournal(*prior, normalized) {
			return ErrStateConflict
		}
		return nil
	}
	if next.RosterRevision != prior.RosterRevision || !slices.Equal(next.Members, prior.Members) {
		return ErrStateConflict
	}
	if prior.Phase == "" {
		if next.Phase != "issue" || next.Generation != prior.Generation+1 || next.Active != prior.Active {
			return ErrStateConflict
		}
		return nil
	}
	if next.Generation != prior.Generation {
		return ErrStateConflict
	}
	if next.Phase == "" {
		expected := prior.Active
		if prior.Phase == "commit" || prior.Phase == "bootstrap" {
			expected = prior.Pending
		} else if prior.Phase != "rollback" {
			return ErrStateConflict
		}
		if next.Active != expected || expected.SecretID == "" {
			return ErrStateConflict
		}
		return nil
	}
	if next.Active != prior.Active || !next.Deadline.Equal(prior.Deadline) || prior.Pending.SecretID != "" && next.Pending != prior.Pending {
		return ErrStateConflict
	}
	switch prior.Phase {
	case "bootstrap":
		if next.Phase == "bootstrap" {
			return nil
		}
	case "issue":
		if next.Phase == "stage" || next.Phase == "rollback" {
			return nil
		}
	case "stage":
		if next.Phase == "commit" || next.Phase == "rollback" {
			return nil
		}
	case "commit":
		if next.Phase == "commit" {
			return nil
		}
	case "rollback":
		if next.Phase == "rollback" {
			return nil
		}
	}
	return ErrStateConflict
}

// Empty storage alone may omit the roster. Bootstrap fixes the initial inventory
// before issuance; subsequent membership changes share the journal stream CAS.
func emptyJournal(j Journal) bool {
	return j.Generation == 0 && j.Active == (hostsecrets.IdentitySecretReference{}) && j.Pending == (hostsecrets.IdentitySecretReference{}) && j.Deadline.IsZero() && j.Phase == "" && j.NextRotation.IsZero() && j.RosterRevision == 0 && len(j.Members) == 0
}

func sameJournal(a, b Journal) bool {
	return a.Generation == b.Generation && a.Active == b.Active && a.Pending == b.Pending && a.Deadline.Equal(b.Deadline) && a.Phase == b.Phase && a.NextRotation.Equal(b.NextRotation) && a.RosterRevision == b.RosterRevision && slices.Equal(a.Members, b.Members)
}

func validJournalRoster(members []RemoteMemberEndpoint) bool {
	if len(members) == 0 || len(members) > 4096 {
		return false
	}
	nodes, endpoints := map[string]bool{}, map[string]bool{}
	for _, member := range members {
		u, err := url.Parse(member.URL)
		if len(member.NodeID) == 0 || len(member.NodeID) > 128 || len(member.URL) > 2048 || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || nodes[member.NodeID] {
			return false
		}
		for _, c := range member.NodeID {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
				return false
			}
		}
		endpoint := strings.ToLower(u.Host)
		if endpoints[endpoint] {
			return false
		}
		nodes[member.NodeID], endpoints[endpoint] = true, true
	}
	return true
}
