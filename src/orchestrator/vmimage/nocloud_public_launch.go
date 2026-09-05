package vmimage

// TSNodePublicLaunchFiles renders the admitted host configuration, manifest,
// grant and public command trust for an OCI metadata shape probe. Credential
// paths are retained; private root files require separate provisioning and are
// never returned here.
func TSNodePublicLaunchFiles(input TSNodeBootstrap) (map[string][]byte, error) {
	config, err := canonicalTSNodeConfig(input.Config, input.ReleasePublicKey)
	if err != nil {
		return nil, err
	}
	manifest, _, err := canonicalDesiredHostManifest(input.DesiredHostManifest)
	if err != nil {
		return nil, err
	}
	grant, err := canonicalInitialGrant(input)
	if err != nil {
		return nil, err
	}
	_, trust, err := canonicalCommandTrust(input.Config)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{tsNodeConfigPath: config, desiredHostManifestPath: manifest}
	for _, file := range append(grant, trust...) {
		files[file.Path] = file.Content
	}
	return files, nil
}
