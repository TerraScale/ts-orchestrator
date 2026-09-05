package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostbootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

func provisionTsNodeSecrets(ctx context.Context, configPath string) error {
	// Validate only public identity before loading NATS credentials, which may
	// not yet exist. Runtime retirement is proven from the private epoch store.
	data, err := readBootstrapConfigFile(configPath, tsNodeMaximumConfigBytes)
	if err != nil {
		return err
	}
	if err = validateTsNodeConfigurationJSON(data); err != nil {
		return err
	}
	var config tsNodeConfigurationFile
	if json.Unmarshal(data, &config) != nil {
		return errors.New("ts-node: invalid initial credential configuration")
	}
	if _, err = hostagent.NewNodeId(config.NodeId); err != nil {
		return err
	}
	if config.DataVolumeRoot != "" && config.DataVolumeRoot != tsNodeDefaultDataVolumeRoot {
		return errors.New("ts-node: initial credential state root differs")
	}
	directory := filepath.Join(tsNodeDefaultDataVolumeRoot, hostagent.TsNodeComponentName, "command-journal")
	return nodeauthority.WithInitialAuthority(directory, config.NodeId, func() error {
		err := hostsecrets.BootstrapFile(ctx, hostsecrets.SeedPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	})
}
func activateTsNodeBeforeNATS(ctx context.Context, configuration tsNodeConfiguration, lifecycle *hostagent.Lifecycle) error {
	if !configuration.BootstrapBeforeNATS {
		return nil
	}
	public, err := readBootstrapConfigFile(configuration.BootstrapPublicKeyFile, 32<<10)
	if err != nil {
		return err
	}
	grant, err := readBootstrapConfigFile(configuration.BootstrapGrantFile, 2<<20)
	if err != nil {
		return err
	}
	return hostbootstrap.RunLocalBootstrap(ctx, hostbootstrap.LocalBootstrapConfig{NodeID: configuration.NodeId, PublicKeyPEM: public, SignedGrant: grant, Lifecycle: lifecycle, ManifestPath: configuration.ManifestPath, InstallRoot: configuration.InstallRoot, Timeout: 2 * time.Minute, CredentialHandoff: func(ctx context.Context, user, digest string) error {
		err := hostsecrets.AdmitOrchestratorOwnershipFile(ctx, hostsecrets.SeedPath, user, digest)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}})
}
