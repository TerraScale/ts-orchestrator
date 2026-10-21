// Package foundationbinding independently verifies logical references to
// resources created by an authenticated regional foundation operation.
package foundationbinding

import (
	"errors"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// Reference returns the sole wire spelling of a supported foundation role.
func Reference(cell, key string) (string, error) {
	if !catalog.IsCell(cell) || !referenceKey(key) {
		return "", errors.New("foundation reference has an unsupported cell or role")
	}
	return "foundation:" + cell + ":" + key, nil
}

// Parse rejects aliases, whitespace, unknown roles and noncanonical cells.
func Parse(reference string) (cell, key string, err error) {
	value, ok := strings.CutPrefix(reference, "foundation:")
	if !ok {
		return "", "", errors.New("foundation reference has an invalid prefix")
	}
	cell, key, ok = strings.Cut(value, ":")
	canonical, err := Reference(cell, key)
	if !ok || err != nil || canonical != reference {
		return "", "", errors.New("foundation reference is not canonical")
	}
	return cell, key, nil
}

func referenceKey(key string) bool {
	switch key {
	case "control_compartment", "network_compartment", "workload_compartment", "subnet", "network_security_group", "workload_network_security_group", "vault", "key":
		return true
	}
	return false
}
