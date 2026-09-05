package hostagent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"

	"strings"
)

func componentExecStart(installRoot string, spec hostmanifest.ComponentSpec) string {
	result := ExecStartPath(installRoot, spec.Name)
	if spec.Arguments == "" {
		return result
	}
	for _, argument := range strings.Split(spec.Arguments, " ") {
		if argument == "@config" {
			argument = filepath.Join(VersionDir(installRoot, spec.Name, spec.Version), spec.Name+".config")
		}
		result += " " + argument
	}
	return result
}

func writeComponentLaunch(directory string, spec hostmanifest.ComponentSpec) error {
	data, err := hostmanifest.CanonicalHostManifestJSON(hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{spec}})
	if err != nil {
		return err
	}
	if err := writeReleaseDigest(filepath.Join(directory, spec.Name+".config"), spec.Configuration); err != nil {
		return err
	}
	return writeReleaseDigest(filepath.Join(directory, spec.Name+".launch.json"), string(data))
}

func readComponentLaunch(directory, component string) (hostmanifest.ComponentSpec, error) {
	path := filepath.Join(directory, component+".launch.json")
	data, info, err := readRegularFileBoundedInfo(path, hostmanifest.MaximumManifestBytes)
	if err != nil {
		return hostmanifest.ComponentSpec{}, err
	}
	if err := requireOwnedRegular(info, false, "component launch manifest"); err != nil {
		return hostmanifest.ComponentSpec{}, err
	}
	if err := requireSameMount(directory, path); err != nil {
		return hostmanifest.ComponentSpec{}, err
	}
	manifest, err := hostmanifest.ParseHostManifest(data)
	if err != nil || len(manifest.Components) != 1 {
		return hostmanifest.ComponentSpec{}, &InvalidDataError{Message: "Invalid immutable component launch manifest."}
	}
	spec := manifest.Components[0]
	canonical, _ := json.Marshal(manifest)
	if !bytes.Equal(data, canonical) || spec.Name != component || spec.Version != filepath.Base(directory) {
		return hostmanifest.ComponentSpec{}, &InvalidDataError{Message: "Component launch manifest does not match its immutable version slot."}
	}
	path = filepath.Join(directory, component+".config")
	config, info, err := readRegularFileBoundedInfo(path, hostmanifest.MaximumConfigurationBytes)
	if err != nil {
		return hostmanifest.ComponentSpec{}, err
	}
	if err := requireOwnedRegular(info, false, "component configuration"); err != nil {
		return hostmanifest.ComponentSpec{}, err
	}
	if err := requireSameMount(directory, path); err != nil {
		return hostmanifest.ComponentSpec{}, err
	}
	if string(config) != spec.Configuration {
		return hostmanifest.ComponentSpec{}, &InvalidDataError{Message: "Immutable component configuration differs from its launch manifest."}
	}
	return spec, nil
}

func verifyExpectedLaunch(directory string, expected hostmanifest.ComponentSpec) error {
	actual, err := readComponentLaunch(directory, expected.Name)
	if err != nil {
		return err
	}
	if actual.Arguments != expected.Arguments || actual.Configuration != expected.Configuration {
		return &InvalidDataError{Message: fmt.Sprintf("Component %s version %s has conflicting immutable launch configuration.", expected.Name, expected.Version)}
	}
	return nil
}

func installedLaunchForSpec(installRoot string, spec hostmanifest.ComponentSpec) (hostmanifest.ComponentSpec, error) {
	launch, err := readComponentLaunch(VersionDir(installRoot, spec.Name, spec.Version), spec.Name)
	if err != nil {
		return hostmanifest.ComponentSpec{}, err
	}
	spec.Arguments, spec.Configuration = launch.Arguments, launch.Configuration
	return spec, nil
}

func hasComponentLaunch(directory, component string) (bool, error) {
	_, err := os.Lstat(filepath.Join(directory, component+".launch.json"))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
