package control

import (
	"fmt"
	"time"
)

// RegionalControllerStatus ports the C# record (JSON source-generated context
// used Web defaults for the wire shape).
type RegionalControllerStatus struct {
	SchemaVersion           int        `json:"schemaVersion"`
	Cell                    string     `json:"cell"`
	Instance                string     `json:"instance"`
	ControlReplicas         int        `json:"controlReplicas"`
	Ready                   bool       `json:"ready"`
	StartedAt               time.Time  `json:"startedAt"`
	ObservedAt              time.Time  `json:"observedAt"`
	Build                   string     `json:"build"`
	Capabilities            []string   `json:"capabilities"`
	AuthorityState          string     `json:"authorityState"`
	IsAuthorityLeader       bool       `json:"isAuthorityLeader"`
	AuthorityEpoch          int64      `json:"authorityEpoch"`
	AuthorityRevision       int64      `json:"authorityRevision"`
	AuthorityLeaseExpiresAt *time.Time `json:"authorityLeaseExpiresAt"`
}

// Validate ports RegionalControllerStatus.Validate; it mirrors the C#
// InvalidOperationException on any invalid member.
func (s *RegionalControllerStatus) Validate(expectedCell string) error {
	invalid := s.SchemaVersion != 2 || s.Cell != expectedCell ||
		s.Instance == "" || s.ControlReplicas != 1 && s.ControlReplicas != 3 && s.ControlReplicas != 5 ||
		!s.Ready || s.StartedAt.After(s.ObservedAt) || s.ObservedAt.After(time.Now().UTC().Add(time.Minute)) ||
		s.Build == "" || len(s.Capabilities) == 0
	if !invalid {
		seen := map[string]bool{}
		for _, capability := range s.Capabilities {
			if capability == "" || seen[capability] {
				invalid = true
				break
			}
			seen[capability] = true
		}
	}
	if !invalid {
		invalid = s.AuthorityState != "leader" && s.AuthorityState != "follower" ||
			s.AuthorityEpoch <= 0 || s.AuthorityRevision <= 0 || s.AuthorityLeaseExpiresAt == nil ||
			!s.AuthorityLeaseExpiresAt.After(s.ObservedAt) ||
			s.IsAuthorityLeader != (s.AuthorityState == "leader")
	}
	if invalid {
		return fmt.Errorf("the regional operator status response is invalid")
	}
	return nil
}
