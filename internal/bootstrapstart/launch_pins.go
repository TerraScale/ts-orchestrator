package bootstrapstart

import (
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
)

const (
	OperatorSSHKeyFilename             = operatorSSHKeyFilename
	ManagedHostImageReceiptFilename    = "managed-host-image-receipt.json"
	ManagedHostImageDelegationFilename = "managed-host-image-delegation.json"
)

var acceptedLaunchNames = [...]string{HostEnrollmentFilename, OperatorSSHKeyFilename,
	ManagedHostImageReceiptFilename, ManagedHostImageDelegationFilename}

func originalAcceptedLaunchNames() []string {
	return []string{HostEnrollmentFilename, OriginalStartupOriginFilename, ManagedHostImageReceiptFilename, ManagedHostImageDelegationFilename}
}

func acceptedLaunchFileNames(pins map[string]string) ([]string, error) {
	if err := identityrekey.ValidateLaunchMaterialPins(pins); err != nil {
		return nil, err
	}
	if _, present := pins[OriginalStartupOriginFilename]; present {
		return originalAcceptedLaunchNames(), nil
	}
	return append([]string(nil), acceptedLaunchNames[:]...), nil
}
