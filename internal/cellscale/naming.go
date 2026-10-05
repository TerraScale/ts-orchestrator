package cellscale

import (
	"fmt"
	"strconv"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
)

// maxOrdinal bounds db node ordinals; no cell policy may exceed it.
const maxOrdinal = 64

// ValidateCell accepts a cell name of the naming scheme, for example gru-1.
func ValidateCell(cell string) error {
	if naming.Validate(cell) != nil || strings.Count(cell, "-") != 1 {
		return fmt.Errorf("cell %q is not a <region>-<index> cell of the naming scheme", cell)
	}
	return nil
}

// NodeName is the static name of db node n of cell, <cell>-db-<n>. It is
// also the OCI display name and the launch key.
func NodeName(cell string, n int) string { return cell + "-" + naming.Member + "-" + strconv.Itoa(n) }

// Ordinal returns the db ordinal of a node of cell.
func Ordinal(cell, node string) (int, bool) {
	suffix, ok := strings.CutPrefix(node, cell+"-"+naming.Member+"-")
	if !ok || naming.Validate(node) != nil {
		return 0, false
	}
	n, err := strconv.Atoi(suffix)
	return n, err == nil && n >= 1 && n <= maxOrdinal
}

// dbNode reports whether name is a db node name of any cell.
func dbNode(name string) bool {
	return naming.Validate(name) == nil && strings.Contains(name, "-"+naming.Member+"-") && !strings.HasSuffix(name, "-data")
}
