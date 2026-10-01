package firecracker

import (
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
)

// NativeProvenance pins the executable that performed the qualification and
// records its embedded module and build metadata alongside the source inputs.
type NativeProvenance struct {
	ExecutableSHA256 string            `json:"executable_sha256"`
	GoVersion        string            `json:"go_version"`
	Main             NativeModule      `json:"main_module"`
	Dependencies     []NativeModule    `json:"dependencies"`
	Settings         map[string]string `json:"build_settings"`
}

type NativeModule struct {
	Path    string        `json:"path"`
	Version string        `json:"version"`
	Sum     string        `json:"sum"`
	Replace *NativeModule `json:"replace,omitzero"`
}

func nativeModule(module debug.Module) NativeModule {
	r := NativeModule{Path: module.Path, Version: module.Version, Sum: module.Sum}
	if module.Replace != nil {
		r.Replace = new(nativeModule(*module.Replace))
	}
	return r
}

func CaptureNativeProvenance() (NativeProvenance, error) {
	h, err := Digest("/proc/self/exe")
	if err != nil {
		return NativeProvenance{}, fmt.Errorf("hash qualification executable: %w", err)
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return NativeProvenance{}, errors.New("qualification executable lacks Go build metadata")
	}
	p := NativeProvenance{ExecutableSHA256: h, GoVersion: info.GoVersion, Main: nativeModule(info.Main), Settings: map[string]string{}}
	for _, dependency := range info.Deps {
		p.Dependencies = append(p.Dependencies, nativeModule(*dependency))
	}
	for _, setting := range info.Settings {
		if slices.Contains([]string{"vcs", "vcs.revision", "vcs.time", "vcs.modified", "GOOS", "GOARCH", "-buildmode", "-compiler", "-trimpath", "CGO_ENABLED"}, setting.Key) {
			p.Settings[setting.Key] = setting.Value
		}
	}
	return p, nil
}

func (p NativeProvenance) VerifyExecutable() error {
	h, err := Digest("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("recheck qualification executable: %w", err)
	}
	if h != p.ExecutableSHA256 {
		return errors.New("qualification executable changed")
	}
	return nil
}
