package hostmanifest

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

const MaximumConfigurationBytes = 64 << 10

var literalArgument = regexp.MustCompile(`^[a-zA-Z0-9_./:=,+-]+$`)

func validateComponentLaunch(spec ComponentSpec) error {
	if len(spec.Arguments) > 4096 || len(spec.Configuration) > MaximumConfigurationBytes || !utf8.ValidString(spec.Configuration) || strings.ContainsRune(spec.Configuration, '\x00') {
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
