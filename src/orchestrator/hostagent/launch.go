package hostagent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const maximumComponentConfigurationBytes = 64 << 10

var literalArgument = regexp.MustCompile(`^[a-zA-Z0-9_./:=,+-]+$`)

func validateComponentLaunch(spec ComponentSpec) error {
	if len(spec.Arguments) > 4096 || len(spec.Configuration) > maximumComponentConfigurationBytes || !utf8.ValidString(spec.Configuration) || strings.ContainsRune(spec.Configuration, '\x00') {
		return &InvalidDataError{Message: "Component launch configuration exceeds its bounds or contains invalid text."}
	}
	if spec.Name == TsNodeComponentName && (spec.Arguments != "" || spec.Configuration != "") {
		return &InvalidDataError{Message: "The ts-node bootstrap owns its launch configuration."}
	}
	references := 0
	if spec.Arguments != "" {
		arguments := strings.Split(spec.Arguments, " ")
		if len(arguments) > 64 {
			return &InvalidDataError{Message: "Too many component arguments."}
		}
		for _, argument := range arguments {
			if argument == "@config" {
				references++
				continue
			}
			if !literalArgument.MatchString(argument) {
				return &InvalidDataError{Message: "Component arguments must be literal tokens without shell or systemd interpolation."}
			}
		}
	}
	if references > 1 || (spec.Configuration != "") != (references == 1) {
		return &InvalidDataError{Message: "Nonempty component configuration requires exactly one @config argument."}
	}
	// This rejects accidental PEM key embedding; it is not a general secret detector.
	if strings.Contains(spec.Configuration, "PRIVATE KEY-----") {
		return &InvalidDataError{Message: "Component configuration must reference separately provisioned private keys."}
	}
	return nil
}

func componentExecStart(installRoot string, spec ComponentSpec) string {
	result := ExecStartPath(installRoot, spec.Name)
	if spec.Arguments == "" {
		return result
	}
	for _, argument := range strings.Split(spec.Arguments, " ") {
		if argument == "@config" {
			argument = InstallDir(installRoot, spec.Name) + "/current/" + spec.Name + ".config"
		}
		result += " " + argument
	}
	return result
}

func writeComponentLaunch(directory string, spec ComponentSpec) error {
	data, err := CanonicalHostManifestJSON(HostManifest{Components: []ComponentSpec{spec}})
	if err != nil {
		return err
	}
	if err := writeReleaseDigest(filepath.Join(directory, spec.Name+".config"), spec.Configuration); err != nil {
		return err
	}
	return writeReleaseDigest(filepath.Join(directory, spec.Name+".launch.json"), string(data))
}

func readComponentLaunch(directory, component string) (ComponentSpec, error) {
	path := filepath.Join(directory, component+".launch.json")
	data, info, err := readRegularFileBoundedInfo(path, hostAgentMaximumManifestBytes)
	if err != nil {
		return ComponentSpec{}, err
	}
	if err := requireOwnedRegular(info, false, "component launch manifest"); err != nil {
		return ComponentSpec{}, err
	}
	if err := requireSameMount(directory, path); err != nil {
		return ComponentSpec{}, err
	}
	manifest, err := ParseHostManifest(data)
	if err != nil || len(manifest.Components) != 1 {
		return ComponentSpec{}, &InvalidDataError{Message: "Invalid immutable component launch manifest."}
	}
	spec := manifest.Components[0]
	canonical, _ := json.Marshal(manifest)
	if !bytes.Equal(data, canonical) || spec.Name != component || spec.Version != filepath.Base(directory) {
		return ComponentSpec{}, &InvalidDataError{Message: "Component launch manifest does not match its immutable version slot."}
	}
	path = filepath.Join(directory, component+".config")
	config, info, err := readRegularFileBoundedInfo(path, maximumComponentConfigurationBytes)
	if err != nil {
		return ComponentSpec{}, err
	}
	if err := requireOwnedRegular(info, false, "component configuration"); err != nil {
		return ComponentSpec{}, err
	}
	if err := requireSameMount(directory, path); err != nil {
		return ComponentSpec{}, err
	}
	if string(config) != spec.Configuration {
		return ComponentSpec{}, &InvalidDataError{Message: "Immutable component configuration differs from its launch manifest."}
	}
	return spec, nil
}

func verifyExpectedLaunch(directory string, expected ComponentSpec) error {
	actual, err := readComponentLaunch(directory, expected.Name)
	if err != nil {
		return err
	}
	if actual.Arguments != expected.Arguments || actual.Configuration != expected.Configuration {
		return &InvalidDataError{Message: fmt.Sprintf("Component %s version %s has conflicting immutable launch configuration.", expected.Name, expected.Version)}
	}
	return nil
}

func installedLaunchForSpec(installRoot string, spec ComponentSpec) (ComponentSpec, error) {
	launch, err := readComponentLaunch(VersionDir(installRoot, spec.Name, spec.Version), spec.Name)
	if err != nil {
		return ComponentSpec{}, err
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
