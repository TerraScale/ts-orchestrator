package vmengineconfig

import (
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

// ValidateStagedManifest checks an initial control launch against the complete
// admitted production manifest. The initial controller cannot expose the engine
// callbacks until its separately signed run handoff is applied.
func (m *Material) ValidateStagedManifest(nodeID, address string, initial, run hostmanifest.HostManifest) error {
	if err := m.ValidateManifest(nodeID, address, run); err != nil {
		return err
	}
	if _, err := hostmanifest.CanonicalHostManifestJSON(initial); err != nil {
		return err
	}
	bad := errors.New("vmengineconfig: initial launch differs from admitted run stage")
	if len(initial.Components) != len(run.Components) {
		return bad
	}
	found := false
	for i, component := range initial.Components {
		final := run.Components[i]
		if component.Name != "orchestrator" {
			if component != final {
				return bad
			}
			continue
		}
		config, initialMode, err := initialgrant.ComponentConfig(component)
		candidate, candidateMode, candidateErr := transitiongrant.ComponentConfig(component)
		admitted := (initialMode && err == nil && config.NodeID == nodeID) || (candidateMode && candidateErr == nil && candidate.NodeID == nodeID)
		if found || !admitted || final.Name != "orchestrator" || final.Arguments != "run --config @config" {
			return bad
		}
		found = true
		// Only the content-addressed launch version and launch settings may
		// change; artifacts, service identity, and resource limits stay pinned.
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
