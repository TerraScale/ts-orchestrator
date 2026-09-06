// Package systemdlimits defines the native service budget for protected keys.
package systemdlimits

// Core disables process core files, which could contain plaintext key material.
const Core = "LimitCORE=0"

// MemoryLock bounds locked mappings without granting CAP_IPC_LOCK. TerraBase
// allows 1024 databases with 32 cached versions each (128 MiB at 4 KiB per
// mapping), plus renewal and I/O headroom. Control services need smaller
// bounded buffers for concurrent Vault operations and provisioning.
func MemoryLock(component string) string {
	if component == "terrabase" || component == "terrabase-server" {
		return "LimitMEMLOCK=268435456"
	}
	return "LimitMEMLOCK=16777216"
}
