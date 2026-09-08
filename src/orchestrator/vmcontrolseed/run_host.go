package vmcontrolseed

import (
	"encoding/json/v2"
	"errors"
	"maps"

	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

type RunHost struct {
	HostID, Cell string
	Membership   initialgrant.Membership
	Predecessor  hostmanifest.HostManifest
	InitialFiles map[string][]byte
}

func (h RunHost) validateMembership(files map[string][]byte) error {
	bad := errors.New("vmcontrolseed: admitted run membership differs")
	if h.Membership.SigningKeyFile != MembershipKeyPath || h.Membership.PinsFile != MembershipPinsPath || digest(files[MembershipPinsPath]) != h.Membership.PinsSHA256 {
		return bad
	}
	_, public, err := directory.RegionalRuntimeMembershipPublicKeyFromPEM(files[MembershipKeyPath])
	if err != nil || public != h.Membership.PublicKey {
		return bad
	}
	var pins map[string]string
	if json.Unmarshal(files[MembershipPinsPath], &pins) != nil || pins[h.HostID] != public {
		return bad
	}
	return nil
}
func protectedRunIdentities(initial, dependencies map[string][]byte) map[string][]byte {
	protected := maps.Clone(initial)
	if protected == nil {
		protected = map[string][]byte{}
	}
	maps.Copy(protected, dependencies)
	return protected
}
func validateRunPredecessor(host RunHost, run hostmanifest.HostManifest) error {
	bad := errors.New("vmcontrolseed: preparation predecessor differs from run inventory")
	if _, err := hostmanifest.CanonicalHostManifestJSON(host.Predecessor); err != nil {
		return err
	}
	if len(host.Predecessor.Components) != len(run.Components) {
		return bad
	}
	found := false
	for i, component := range host.Predecessor.Components {
		final := run.Components[i]
		if component.Name != "orchestrator" {
			if component != final {
				return bad
			}
			continue
		}
		if found || final.Name != "orchestrator" {
			return bad
		}
		found = true
		initial, initialMode, initialErr := initialgrant.ComponentConfig(component)
		candidate, candidateMode, candidateErr := transitiongrant.ComponentConfig(component)
		if !(initialMode && initialErr == nil && initial.NodeID == host.HostID && initial.Cell == host.Cell) && !(candidateMode && candidateErr == nil && candidate.NodeID == host.HostID && candidate.Region == host.Cell) {
			return bad
		}
		component.Version, component.Arguments, component.Configuration = final.Version, final.Arguments, final.Configuration
		if component != final {
			return bad
		}
	}
	if !found {
		return bad
	}
	return nil
}
