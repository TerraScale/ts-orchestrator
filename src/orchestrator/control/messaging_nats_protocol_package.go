package control

// NatsProtocolPackageBytes mirrors NatsProtocolPackage.Bytes: the immutable
// canonical protocol package the controller compares against the object-store
// copy.
var NatsProtocolPackageBytes = []byte(`{"name":"terrascale-orchestrator","protocol":2}`)

// messagingCellTokenIsValid replicates the root CellTokenRule.IsValid (the Go
// control package cannot wait for the root-file wave; the rule is 1..63
// lowercase DNS-style characters that neither start nor end with a dash). The
// protocol package replicates the same rule privately.
func messagingCellTokenIsValid(cell string) bool {
	if len(cell) < 1 || len(cell) > 63 {
		return false
	}

	if cell[0] == '-' || cell[len(cell)-1] == '-' {
		return false
	}

	for index := 0; index < len(cell); index++ {
		character := cell[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}

		return false
	}

	return true
}
