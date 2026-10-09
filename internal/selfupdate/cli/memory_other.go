//go:build !linux

package cli

// memoryRuntime mounts nothing off Linux: nodes run Linux.
var memoryRuntime = func(string) error { return nil }
