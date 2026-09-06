package main

import (
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
)

func configurePlacementBroker(config *bootstrap.NatsServerConfig, lookup envLookup) error {
	path, provided := lookup(placementpublisher.BrokerGrantsEnvironment)
	if !provided {
		return nil
	}
	if path == "" {
		return errors.New("placement broker: explicit grant file path is empty")
	}
	raw, err := bootstrapcredentials.ReadFile(path, false, placementpublisher.MaximumBrokerGrantsBytes)
	if err != nil {
		return err
	}
	grants, err := placementpublisher.ParseBrokerGrants(raw)
	if err != nil {
		return err
	}
	// Non-broker hosts carry the same public grant inventory for the signed
	// estate, but never create a broker or assume quorum from that inventory.
	if config != nil {
		config.PlacementHosts = grants
	}
	return nil
}
