package bootstrap

import (
	"encoding/base64"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
)

// ValidateControlRuntimeDeclarations validates logical host identities before
// OCI allocates instance IDs. No connection or observed evidence is created.
func ValidateControlRuntimeDeclarations(stores []string, members []ControlRuntimeMember, plans []ControlRuntimeActionPlan) error {
	return validateControlRuntimeDeclarations(stores, members, plans, false)
}

// ValidateLiveControlRuntimeDeclarations validates owner-pinned inventory for
// actions whose election identity will be resolved after their host handoffs.
// It does not produce evidence or authorize mutations without live lease checks.
func ValidateLiveControlRuntimeDeclarations(stores []string, members []ControlRuntimeMember, plans []ControlRuntimeActionPlan) error {
	return validateControlRuntimeDeclarations(stores, members, plans, true)
}

func validateControlRuntimeDeclarations(stores []string, members []ControlRuntimeMember, plans []ControlRuntimeActionPlan, resolveLive bool) error {
	runtime := &NATSControlRuntime{config: NATSControlRuntimeConfig{Stores: map[string]ControlNATSStore{}}, members: map[string]ControlRuntimeMember{}}
	for _, name := range stores {
		if name == "" {
			return ErrControlProviderInvalid
		}
		if _, ok := runtime.config.Stores[name]; ok {
			return ErrControlProviderInvalid
		}
		runtime.config.Stores[name] = ControlNATSStore{}
	}
	servers := map[string]bool{}
	for _, member := range members {
		key, err := base64.StdEncoding.Strict().DecodeString(member.IdentityPublicKey)
		if err != nil || !validControlMembershipPublicKey(key) || base64.StdEncoding.EncodeToString(key) != member.IdentityPublicKey || member.MemberID != member.HostID || !validControlRegion(member.Region) || member.Instance == "" || member.ServerName == "" || servers[member.ServerName] {
			return ErrControlProviderInvalid
		}
		if _, err := hostagent.NewNodeId(member.HostID); err != nil {
			return err
		}
		if _, ok := runtime.members[member.MemberID]; ok {
			return ErrControlProviderInvalid
		}
		if _, ok := runtime.config.Stores[member.Store]; !ok {
			return ErrControlProviderInvalid
		}
		servers[member.ServerName] = true
		runtime.members[member.MemberID] = member
	}
	if len(members) == 0 || len(plans) == 0 {
		return errors.New("bootstrap: complete logical runtime declarations required")
	}
	actions := map[string]bool{}
	for _, plan := range plans {
		key := runtimeActionKey(plan.Kind, plan.Region, plan.ExpectedEpoch, plan.TargetEpoch)
		if actions[key] {
			return ErrControlProviderInvalid
		}
		actions[key] = true
		if err := runtime.validatePlanMode(plan, resolveLive); err != nil {
			return err
		}
	}
	return nil
}
