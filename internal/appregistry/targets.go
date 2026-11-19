package appregistry

import "slices"

type Target struct {
	Service  string
	Package  string
	Workflow string
}

var deployed = []Target{
	{"terrabase", "terrabase", "TerraScale/terrascale/.github/workflows/ci.yml@refs/heads/main"},
	{"ts-auth", "ts-auth", "TerraScale/terrascale/.github/workflows/ci.yml@refs/heads/main"},
	{"ts-dashboard", "terrascale-dashboard", "TerraScale/terrascale/.github/workflows/images-ghcr.yml@refs/heads/main"},
}

func Deployed() []Target {
	return slices.Clone(deployed)
}

func Targets() []Target {
	return slices.Concat(deployed, []Target{
		{"app-canary", "app-canary", "TerraScale/ts-orchestrator/.github/workflows/app-canary.yml@refs/heads/main"},
	})
}
