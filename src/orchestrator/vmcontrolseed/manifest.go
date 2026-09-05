package vmcontrolseed

import (
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
)

// LaunchManifest binds the explicit initial role before the existing owner grant
// signs the complete host manifest. Both GRU hosts retain their local components.
func (m Material) LaunchManifest(raw []byte) (hostmanifest.HostManifest, error) {
	if err := m.Validate(); err != nil {
		return hostmanifest.HostManifest{}, err
	}
	desired, err := hostmanifest.ParseHostManifest(raw)
	if err != nil {
		return hostmanifest.HostManifest{}, err
	}
	found := false
	for i := range desired.Components {
		if desired.Components[i].Name == "orchestrator" {
			if found {
				return hostmanifest.HostManifest{}, errors.New("vmcontrolseed: repeated orchestrator component")
			}
			found = true
			desired.Components[i].Arguments = Arguments
			desired.Components[i].Configuration = m.Settings
		}
	}
	if !found {
		return hostmanifest.HostManifest{}, errors.New("vmcontrolseed: orchestrator component missing")
	}
	return bootstrap.PlanControlLaunchManifest(desired)
}
