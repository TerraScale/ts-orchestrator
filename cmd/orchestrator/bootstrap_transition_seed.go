package main

import (
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

// OCI bootstrap seeds provision this dedicated root credential before services
// start. The later signed plan still has to bind its public key; no seed grants
// permission to acknowledge a plan or re-sign an existing receipt.
func bootstrapStorageTransitionReceiptPath(manifest hostmanifest.HostManifest) (string, error) {
	path := ""
	for _, spec := range manifest.Components {
		initial, found, err := initialgrant.ComponentConfig(spec)
		if err != nil {
			return "", err
		}
		candidate, prepared, err := transitiongrant.ComponentConfig(spec)
		if err != nil {
			return "", err
		}
		var d controltransition.Delivery
		if found {
			d = initial.StorageTransition
		}
		if prepared {
			d = candidate.StorageTransition
		}
		if d == (controltransition.Delivery{}) {
			continue
		}
		if path != "" || d.ReceiptPrivateKeyFile != hostsecrets.StorageTransitionReceiptKeyPath {
			return "", errors.New("control: transition receipt requires its dedicated root Vault destination")
		}
		path = d.ReceiptPrivateKeyFile
	}
	return path, nil
}

func validateBootstrapStorageTransitionSeed(path string, seed hostsecrets.Seed, identities map[string]string, signers map[string]*security.CommandSignatureSigner, hosts map[string]string, node string) error {
	bad := errors.New("control: transition receipt Vault key differs from host admission or reuses another credential")
	found := false
	for _, entry := range seed.Entries {
		if entry.Destination == hostsecrets.StorageTransitionReceiptKeyPath {
			found = true
		}
	}
	if path == "" {
		if found {
			return bad
		}
		return nil
	}
	id := identities[path]
	if !found || id == "" {
		return bad
	}
	for other, key := range identities {
		if other != path && key == id {
			return bad
		}
	}
	for _, signer := range signers {
		if signer != nil && signer.PublicKeyID() == id {
			return bad
		}
	}
	if prior := hosts[id]; prior != "" && prior != node {
		return bad
	}
	hosts[id] = node
	return nil
}
