package app

import (
	"fmt"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/roleidentity"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func validateWorkloadProfiles(cell string, profiles map[string]WorkloadProfile) error {
	for role, profile := range profiles {
		if !grantToken.MatchString(role) || profile.Resources.CPU <= 0 || profile.Resources.CPU > 4096 ||
			profile.Resources.MemoryBytes <= 0 || profile.Resources.MemoryBytes > 1<<50 ||
			profile.Resources.DiskBytes <= 0 || profile.Resources.DiskBytes > 1<<50 {
			return fmt.Errorf("invalid workload resource profile for role %q", role)
		}
		if len(profile.Args) > 64 || len(profile.Env) > 64 {
			return fmt.Errorf("workload profile for %q exceeds argument or environment limit", role)
		}
		for _, arg := range profile.Args {
			if len(arg) > 4096 {
				return fmt.Errorf("workload argument for %q is too long", role)
			}
		}
		for key, value := range profile.Env {
			if key == "" || len(value) > 4096 {
				return fmt.Errorf("workload environment for %q is invalid", role)
			}
		}
		for key := range profile.Secrets {
			if role == terrabase.Role && !vaultsecret.FileKey(key) {
				return fmt.Errorf("workload profile for %q takes only Vault secret files (keys ending in _FILE)", role)
			}
			if roleidentity.Reserved(role, key) {
				return fmt.Errorf("workload profile for %q: the host sets %s for its NATS identity", role, key)
			}
		}
		for key := range profile.Env {
			if roleidentity.Reserved(role, key) {
				return fmt.Errorf("workload profile for %q: the host sets %s for its NATS identity", role, key)
			}
		}
		if err := vaultsecret.ValidateRefs(cell, role, profile.Secrets, profile.Env); err != nil {
			return fmt.Errorf("workload profile for %q: %w", role, err)
		}
		// Secret names start with the role, so a longer role would share them.
		for other := range profiles {
			if len(profile.Secrets) != 0 && strings.HasPrefix(other, role+"-") {
				return fmt.Errorf("workload profile for %q names Vault secrets, so no role may extend its name (%q)", role, other)
			}
		}
		// A terrabase profile with settings configures the C# TerraBase
		// binary. Arguments would override the host-owned settings.
		if role == terrabase.Role && len(profile.Env) != 0 {
			if _, err := terrabase.ParseProfile(profile.Env); err != nil {
				return fmt.Errorf("workload profile for %q: %w", role, err)
			}
			if len(profile.Args) != 0 {
				return fmt.Errorf("workload profile for %q sets TerraBase settings only through env", role)
			}
		}
		// The ts-auth profile is signed and readable: it must hold every
		// setting and name its secrets, which hosts read from the Vault.
		if role == tsauth.Role {
			if err := tsauth.ValidateProfile(cell, profile.Args, profile.Env, profile.Secrets); err != nil {
				return fmt.Errorf("workload profile for %q: %w", role, err)
			}
			if err := tsauth.ValidateMembers(profile.Env, profiles[terrabase.Role].Env); err != nil {
				return fmt.Errorf("workload profile for %q: %w", role, err)
			}
		}
	}
	return nil
}
