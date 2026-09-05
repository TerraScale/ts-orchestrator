package natspolicy

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// NatsControlAccountKind is the closed set of account kinds of the NATS
// control network. The kinds separate infrastructure
// administration, global authority, the global directory read service, one
// regional controller scope per Region, per-host-agent scopes, CI
// coordinators, isolated CI runners, read-only monitoring, and break-glass
// recovery. Standing write permissions are disjoint: no control subject may be
// published by two different account kinds.
type NatsControlAccountKind int

const (
	NatsControlAccountKindUnspecified                  NatsControlAccountKind = 0
	NatsControlAccountKindInfrastructureAdministration NatsControlAccountKind = 1
	NatsControlAccountKindGlobalAuthority              NatsControlAccountKind = 2
	NatsControlAccountKindGlobalDirectoryReadService   NatsControlAccountKind = 3
	NatsControlAccountKindRegionalController           NatsControlAccountKind = 4
	NatsControlAccountKindHostAgent                    NatsControlAccountKind = 5
	NatsControlAccountKindCiCoordinator                NatsControlAccountKind = 6
	NatsControlAccountKindCiIsolatedRunner             NatsControlAccountKind = 7
	NatsControlAccountKindReadOnlyMonitoring           NatsControlAccountKind = 8
	NatsControlAccountKindBreakGlassRecovery           NatsControlAccountKind = 9
)

func (k NatsControlAccountKind) String() string {
	switch k {
	case NatsControlAccountKindInfrastructureAdministration:
		return "InfrastructureAdministration"
	case NatsControlAccountKindGlobalAuthority:
		return "GlobalAuthority"
	case NatsControlAccountKindGlobalDirectoryReadService:
		return "GlobalDirectoryReadService"
	case NatsControlAccountKindRegionalController:
		return "RegionalController"
	case NatsControlAccountKindHostAgent:
		return "HostAgent"
	case NatsControlAccountKindCiCoordinator:
		return "CiCoordinator"
	case NatsControlAccountKindCiIsolatedRunner:
		return "CiIsolatedRunner"
	case NatsControlAccountKindReadOnlyMonitoring:
		return "ReadOnlyMonitoring"
	case NatsControlAccountKindBreakGlassRecovery:
		return "BreakGlassRecovery"
	default:
		return "Unspecified"
	}
}

// NatsControlAccountScope is one instantiated account scope. Grant patterns
// are generated from the checked-in protocol manifest: the <region>
// placeholder is replaced with one strict lowercase Region token and the
// <agent-hash> placeholder with the fixed hash of the admitted agent
// identity, so no scope can ever widen past its Region or its agent.
type NatsControlAccountScope struct {
	Kind        NatsControlAccountKind
	RegionToken string
	AgentHash   string
	Publish     []string
	Subscribe   []string
}

// NatsControlAccountScopeCreate instantiates one account scope. An empty
// regionToken or agentIdentity means the optional argument is absent.
// Region-scoped kinds require one strict lowercase Region
// token; every kind whose grants carry the agent-hash placeholder
// additionally requires the admitted agent identity, which is reduced to its
// fixed hash before any subject is composed. No other combination of scope
// inputs is accepted.
func NatsControlAccountScopeCreate(
	kind NatsControlAccountKind,
	regionToken string,
	agentIdentity string,
) (*NatsControlAccountScope, error) {
	grants, err := NatsControlAccountModel.GrantTemplateFor(kind)
	if err != nil {
		return nil, err
	}

	if grants.RegionScoped {
		if regionToken == "" {
			return nil, errors.New(
				"The Region-scoped account kind requires one strict lowercase Region subject token. (Parameter 'regionToken')")
		}

		if _, ok := NatsSubjectTaxonomy.TryMapSubjectTokenToRegionCode(regionToken); !ok {
			return nil, errors.New(
				"The Region-scoped account kind requires one strict lowercase Region subject token. (Parameter 'regionToken')")
		}
	} else if regionToken != "" {
		return nil, errors.New(
			"The account kind is not Region-scoped and must not pin a Region token. (Parameter 'regionToken')")
	}

	needsAgentHash := false
	for _, template := range grants.Publish {
		if strings.Contains(template, NatsSubjectTaxonomy.AgentHashPlaceholderToken()) {
			needsAgentHash = true
			break
		}
	}

	if !needsAgentHash {
		for _, template := range grants.Subscribe {
			if strings.Contains(template, NatsSubjectTaxonomy.AgentHashPlaceholderToken()) {
				needsAgentHash = true
				break
			}
		}
	}

	agentHash := ""
	if needsAgentHash {
		if agentIdentity == "" {
			return nil, errors.New(
				"The account kind grants agent-hash scoped subjects and requires the admitted agent identity. (Parameter 'agentIdentity')")
		}

		token, err := NatsSubjectTaxonomy.HostAgentSubjectToken(agentIdentity)
		if err != nil {
			return nil, err
		}

		agentHash = token
	} else if agentIdentity != "" {
		return nil, errors.New(
			"The account kind holds no agent-hash scoped grant and must not pin an agent identity. (Parameter 'agentIdentity')")
	}

	return &NatsControlAccountScope{
		Kind:        kind,
		RegionToken: regionToken,
		AgentHash:   agentHash,
		Publish:     instantiateGrantTemplates(grants.Publish, regionToken, agentHash),
		Subscribe:   instantiateGrantTemplates(grants.Subscribe, regionToken, agentHash),
	}, nil
}

func instantiateGrantTemplates(templates []string, regionToken, agentHash string) []string {
	materialized := make([]string, len(templates))
	for index, template := range templates {
		materialized[index] = materializeGrantTemplate(template, regionToken, agentHash)
	}

	return materialized
}

// NatsControlAccountModel is the closed account model, generated from and
// validated against the checked-in protocol manifest. Completeness proves:
// every manifest kind maps to one account kind
// in both directions, every standing grant is a closed control-family
// permission (or, for the infrastructure kind, platform-reserved surface),
// write grants are pairwise disjoint across kinds, read-only kinds hold no
// write grants, and break-glass recovery holds no standing grants at all.
var NatsControlAccountModel natsControlAccountModel

type natsControlAccountModel struct{}

var manifestKindsOnce sync.Once

// Kinds returns the closed account kinds, generated from the checked-in
// protocol manifest.
func (natsControlAccountModel) Kinds() []NatsControlAccountKind {
	manifestKindsOnce.Do(func() {
		violations := NatsControlAccountModel.CompletenessViolations()
		if len(violations) > 0 {
			panic("The checked-in protocol manifest disagrees with the NATS control account model: " +
				strings.Join(violations, "; "))
		}
	})

	kinds := []NatsControlAccountKind{}
	for _, grants := range ProtocolManifestLoaded().AccountKinds {
		if kind, ok := tryMapAccountKindName(grants.Kind); ok {
			kinds = append(kinds, kind)
		} else {
			kinds = append(kinds, NatsControlAccountKindUnspecified)
		}
	}

	return kinds
}

// IsComplete reports whether the model has no completeness violations.
func (natsControlAccountModel) IsComplete() bool {
	return len(NatsControlAccountModel.CompletenessViolations()) == 0
}

// CompletenessViolations lists every disagreement between the protocol
// manifest, the account kinds, and the disjointness contract.
func (natsControlAccountModel) CompletenessViolations() []string {
	manifest := ProtocolManifestLoaded()
	violations := []string{}

	manifestKinds := map[string]struct{}{}
	for _, grants := range manifest.AccountKinds {
		manifestKinds[grants.Kind] = struct{}{}
	}

	for _, kind := range enumerateAccountKinds() {
		if _, present := manifestKinds[accountKindName(kind)]; !present {
			violations = append(violations, "The manifest is missing the account kind '"+accountKindName(kind)+"'.")
		}
	}

	for _, grants := range manifest.AccountKinds {
		if _, ok := tryMapAccountKindName(grants.Kind); !ok {
			violations = append(violations, "The manifest declares the unknown account kind '"+grants.Kind+"'.")
		}
	}

	publishOwners := map[string]string{}
	for _, grants := range manifest.AccountKinds {
		kindName := grants.Kind
		if grants.ReadOnly && len(grants.Publish) > 0 {
			violations = append(violations, "The read-only account kind '"+kindName+"' holds write grants.")
		}

		if grants.BreakGlass && (len(grants.Publish) > 0 || len(grants.Subscribe) > 0) {
			violations = append(violations, "The break-glass account kind '"+kindName+"' holds standing grants.")
		}

		if grants.AgentHashScoped && !grants.RegionScoped {
			violations = append(violations, "The account kind '"+kindName+"' is agent-hash scoped without a Region scope.")
		}

		templates := append(append([]string{}, grants.Publish...), grants.Subscribe...)
		for _, template := range templates {
			carriesRegion := strings.Contains(template, NatsSubjectTaxonomy.RegionPlaceholderToken())
			carriesAgentHash := strings.Contains(template, NatsSubjectTaxonomy.AgentHashPlaceholderToken())
			materialized := materializeGrantTemplate(template, sampleRegionToken, sampleAgentHashToken)

			if grants.PlatformOnly {
				if !isPlatformPattern(materialized) {
					violations = append(violations,
						"The infrastructure account kind '"+kindName+"' grants '"+template+
							"' outside the platform-reserved surface.")
				}
			} else if isPlatformPattern(materialized) {
				violations = append(violations,
					"The account kind '"+kindName+"' grants the non-closed permission '"+template+"'.")
			} else if ok, err := NatsSubjectTaxonomy.TryValidatePermissionPattern(materialized); !ok || err != NatsSubjectPermissionErrorNone {
				violations = append(violations,
					"The account kind '"+kindName+"' grants the non-closed permission '"+template+"'.")
			}

			if grants.RegionScoped && !carriesRegion && carriesAgentHash {
				violations = append(violations,
					"The Region-scoped account kind '"+kindName+"' grants '"+template+"' without a Region pin.")
			}

			if grants.AgentHashScoped && !carriesAgentHash {
				violations = append(violations,
					"The agent-hash scoped account kind '"+kindName+"' grants '"+template+"' without an agent-hash pin.")
			}
		}

		for _, pattern := range grants.Publish {
			if owner, taken := publishOwners[pattern]; taken {
				violations = append(violations,
					"The write permission '"+pattern+"' is granted to both '"+owner+"' and '"+kindName+"'.")
			} else {
				publishOwners[pattern] = kindName
			}
		}
	}

	return violations
}

const sampleRegionToken = "gru"

var sampleAgentHashToken = func() string {
	token, err := NatsSubjectTaxonomy.HostAgentSubjectToken("completeness-sample-host-agent")
	if err != nil {
		panic(err)
	}

	return token
}()

func materializeGrantTemplate(template, regionToken, agentHashToken string) string {
	return strings.ReplaceAll(
		strings.ReplaceAll(template, NatsSubjectTaxonomy.RegionPlaceholderToken(), regionToken),
		NatsSubjectTaxonomy.AgentHashPlaceholderToken(), agentHashToken)
}

// GrantTemplateFor returns the manifest grant template of one account kind.
func (natsControlAccountModel) GrantTemplateFor(kind NatsControlAccountKind) (ProtocolAccountKindGrants, error) {
	if kind == NatsControlAccountKindUnspecified {
		return ProtocolAccountKindGrants{}, errors.New(
			"Specified argument was out of the range of valid values. (Parameter 'kind', actual value 0)")
	}

	name := accountKindName(kind)
	for _, candidate := range ProtocolManifestLoaded().AccountKinds {
		if candidate.Kind == name {
			return candidate, nil
		}
	}

	return ProtocolAccountKindGrants{}, errors.New(
		"The checked-in protocol manifest does not declare the account kind '" + name + "'.")
}

func enumerateAccountKinds() []NatsControlAccountKind {
	return []NatsControlAccountKind{
		NatsControlAccountKindInfrastructureAdministration,
		NatsControlAccountKindGlobalAuthority,
		NatsControlAccountKindGlobalDirectoryReadService,
		NatsControlAccountKindRegionalController,
		NatsControlAccountKindHostAgent,
		NatsControlAccountKindCiCoordinator,
		NatsControlAccountKindCiIsolatedRunner,
		NatsControlAccountKindReadOnlyMonitoring,
		NatsControlAccountKindBreakGlassRecovery,
	}
}

func tryMapAccountKindName(kindName string) (NatsControlAccountKind, bool) {
	switch kindName {
	case "infrastructure-administration":
		return NatsControlAccountKindInfrastructureAdministration, true
	case "global-authority":
		return NatsControlAccountKindGlobalAuthority, true
	case "global-directory-read-service":
		return NatsControlAccountKindGlobalDirectoryReadService, true
	case "regional-controller":
		return NatsControlAccountKindRegionalController, true
	case "host-agent":
		return NatsControlAccountKindHostAgent, true
	case "ci-coordinator":
		return NatsControlAccountKindCiCoordinator, true
	case "ci-isolated-runner":
		return NatsControlAccountKindCiIsolatedRunner, true
	case "read-only-monitoring":
		return NatsControlAccountKindReadOnlyMonitoring, true
	case "break-glass-recovery":
		return NatsControlAccountKindBreakGlassRecovery, true
	default:
		return NatsControlAccountKindUnspecified, false
	}
}

func accountKindName(kind NatsControlAccountKind) string {
	switch kind {
	case NatsControlAccountKindInfrastructureAdministration:
		return "infrastructure-administration"
	case NatsControlAccountKindGlobalAuthority:
		return "global-authority"
	case NatsControlAccountKindGlobalDirectoryReadService:
		return "global-directory-read-service"
	case NatsControlAccountKindRegionalController:
		return "regional-controller"
	case NatsControlAccountKindHostAgent:
		return "host-agent"
	case NatsControlAccountKindCiCoordinator:
		return "ci-coordinator"
	case NatsControlAccountKindCiIsolatedRunner:
		return "ci-isolated-runner"
	case NatsControlAccountKindReadOnlyMonitoring:
		return "read-only-monitoring"
	case NatsControlAccountKindBreakGlassRecovery:
		return "break-glass-recovery"
	default:
		panic(fmt.Sprintf("The account kind is unspecified. (Parameter 'kind', actual value %d)", int(kind)))
	}
}

func isPlatformPattern(pattern string) bool {
	firstToken := strings.Split(pattern, ".")[0]
	return isPlatformReservedRoot(firstToken)
}
