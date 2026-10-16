package manager

import "strings"

// IsManagedSetupKeyName recognizes the reserved name format, not ownership.
// Only the durable enrollment intent authorizes mutation of an operation's key.
func IsManagedSetupKeyName(canonical, name string) bool {
	id, ok := strings.CutPrefix(name, canonical+"-enrollment-")
	return ok && len(id) == 32 && strings.Trim(id, "0123456789abcdef") == ""
}
