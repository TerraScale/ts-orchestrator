package cli

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/app"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
)

func attachReviewedControllerConfig(manifest *bootstrap.Manifest, configPath, configSHA,
	intentPath, intentSHA, regionPath, regionSHA, placementPath, placementSHA string,
) error {
	if manifest == nil {
		return errors.New("controller manifest is absent")
	}
	configWire, err := readPinnedControllerFile(configPath, configSHA, bootstrap.MaxControllerConfigBytes)
	if err != nil {
		return fmt.Errorf("reviewed controller config: %w", err)
	}
	files := make([]bootstrap.ControllerConfigFile, 0, len(bootstrap.ControllerConfigFileNames))
	for index, source := range []struct{ path, digest string }{
		{intentPath, intentSHA}, {regionPath, regionSHA}, {placementPath, placementSHA},
	} {
		wire, err := readPinnedControllerFile(source.path, source.digest, bootstrap.MaxControllerSidecarBytes)
		if err != nil {
			return fmt.Errorf("reviewed %s: %w", bootstrap.ControllerConfigFileNames[index], err)
		}
		files = append(files, bootstrap.ControllerConfigFile{
			Name: bootstrap.ControllerConfigFileNames[index], SHA256: source.digest, Bytes: wire,
		})
	}
	if len(manifest.ControllerConfig) != 0 && !bytes.Equal(manifest.ControllerConfig, configWire) ||
		manifest.ControllerConfigSHA256 != "" && manifest.ControllerConfigSHA256 != configSHA ||
		len(manifest.ControllerFiles) != 0 && !sameControllerFiles(manifest.ControllerFiles, files) {
		return errors.New("candidate controller config conflicts with reviewed exact bytes")
	}
	manifest.ControllerConfig = configWire
	manifest.ControllerConfigSHA256 = configSHA
	manifest.ControllerFiles = files
	_, err = app.ValidateSignedControllerConfig(*manifest, "")
	return err
}

func readPinnedControllerFile(path, digest string, maximum int) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || len(digest) != 64 {
		return nil, errors.New("absolute path and lowercase SHA-256 are required")
	}
	wire, err := readBoundedRegular(path, int64(maximum))
	if err != nil {
		return nil, err
	}
	if len(wire) == 0 || !matchesSHA256(wire, digest) {
		return nil, errors.New("exact reviewed SHA-256 does not match")
	}
	return wire, nil
}

func sameControllerFiles(left, right []bootstrap.ControllerConfigFile) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Name != right[index].Name || left[index].SHA256 != right[index].SHA256 ||
			!bytes.Equal(left[index].Bytes, right[index].Bytes) {
			return false
		}
	}
	return true
}
