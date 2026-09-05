package natspolicy

import (
	"slices"
	"strings"
	"testing"
)

var testRegions = []string{"gru", "sfo", "fra"}

const gruAgent = "host/gru/agent-07"

func TestTheAccountModelIsCompleteAgainstTheManifest(t *testing.T) {
	if !NatsControlAccountModel.IsComplete() {
		t.Fatalf("completeness violations: %v", NatsControlAccountModel.CompletenessViolations())
	}

	if violations := NatsControlAccountModel.CompletenessViolations(); len(violations) != 0 {
		t.Fatalf("violations = %v", violations)
	}
}

func TestTheClosedAccountKindsAreExactlyTheGoalKindsInBothDirections(t *testing.T) {
	expectedKinds := []NatsControlAccountKind{
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

	kinds := NatsControlAccountModel.Kinds()
	if len(kinds) != len(expectedKinds) {
		t.Fatalf("kinds = %v", kinds)
	}

	for _, kind := range expectedKinds {
		if !slices.Contains(kinds, kind) {
			t.Fatalf("kind %v missing", kind)
		}
	}

	manifestKinds := []string{}
	for _, grants := range ProtocolManifestLoaded().AccountKinds {
		manifestKinds = append(manifestKinds, grants.Kind)
	}

	expectedNames := []string{
		"infrastructure-administration",
		"global-authority",
		"global-directory-read-service",
		"regional-controller",
		"host-agent",
		"ci-coordinator",
		"ci-isolated-runner",
		"read-only-monitoring",
		"break-glass-recovery",
	}

	for _, name := range expectedNames {
		if !slices.Contains(manifestKinds, name) {
			t.Fatalf("manifest kind %q missing", name)
		}
	}
}

func allTestScopes(t *testing.T) []*NatsControlAccountScope {
	t.Helper()
	scopes := []*NatsControlAccountScope{
		mustScope(t, NatsControlAccountKindInfrastructureAdministration, "", ""),
		mustScope(t, NatsControlAccountKindGlobalAuthority, "", ""),
		mustScope(t, NatsControlAccountKindGlobalDirectoryReadService, "", ""),
		mustScope(t, NatsControlAccountKindCiCoordinator, "", ""),
		mustScope(t, NatsControlAccountKindCiIsolatedRunner, "", ""),
		mustScope(t, NatsControlAccountKindBreakGlassRecovery, "", ""),
	}

	for _, region := range testRegions {
		scopes = append(scopes,
			mustScope(t, NatsControlAccountKindRegionalController, region, "host/"+region+"/agent-07"),
			mustScope(t, NatsControlAccountKindHostAgent, region, "host/"+region+"/agent-07"),
			mustScope(t, NatsControlAccountKindReadOnlyMonitoring, region, ""))
	}

	return scopes
}

func mustScope(t *testing.T, kind NatsControlAccountKind, regionToken, agentIdentity string) *NatsControlAccountScope {
	t.Helper()
	scope, err := NatsControlAccountScopeCreate(kind, regionToken, agentIdentity)
	if err != nil {
		t.Fatalf("scope creation failed for %v: %v", kind, err)
	}

	return scope
}

func TestEveryStandingGrantIsAClosedPermissionOfItsOwnSurface(t *testing.T) {
	for _, scope := range allTestScopes(t) {
		patterns := append(append([]string{}, scope.Publish...), scope.Subscribe...)
		for _, pattern := range patterns {
			if scope.Kind == NatsControlAccountKindInfrastructureAdministration {
				if !strings.HasPrefix(pattern, "$") {
					t.Fatalf("the infrastructure kind only ever touches platform-reserved surface: %q", pattern)
				}

				continue
			}

			if ok, err := NatsSubjectTaxonomy.TryValidatePermissionPattern(pattern); !ok || err != NatsSubjectPermissionErrorNone {
				t.Fatalf("account kind %v must only hold closed v1 permissions: %q (%v)", scope.Kind, pattern, err)
			}
		}
	}
}

func controlSubjectCorpus(t *testing.T) []string {
	t.Helper()
	corpus := []string{}
	for _, region := range testRegions {
		corpus = append(corpus,
			"ts.orch.v1."+region+".desired.gitops",
			"ts.orch.v1."+region+".command.delivery",
			"ts.orch.v1."+region+".command.journal.create",
			"ts.orch.v1."+region+".query.health",
			"ts.orch.v1."+region+".audit.event.7",
			"ts.orch.v1."+region+".observation.runtime.started.controller-1")

		token := must(t, func() (string, error) {
			return NatsSubjectTaxonomy.HostAgentSubjectToken("host/" + region + "/agent-07")
		})
		corpus = append(corpus,
			"ts.orch.v1."+region+".agent."+token+".command.start",
			"ts.orch.v1."+region+".agent."+token+".observation.heartbeat",
			"ts.orch.v1."+region+".agent."+token+".ack.42")
	}

	runnerToken := must(t, func() (string, error) { return NatsSubjectTaxonomy.HostAgentSubjectToken("runner-7") })
	return append(corpus,
		"ts.orch.v1.global.desired.gitops.gru",
		"ts.orch.v1.global.release.accepted.r7",
		"ts.orch.v1.global.release.ci.forgejo",
		"ts.orch.v1.global.release.ci.job.zone-1."+runnerToken[:NatsSubjectTaxonomy.AgentHashTokenLength()],
		"ts.orch.v1.global.release.ci.runtime-proof.build-9",
		"ts.orch.v1.global.query.cells",
		"$SYS.REQ.SERVER.PING")
}

func corpusMatches(pattern, subject string) bool {
	concrete, concreteErr := ConcreteSubjectTryParse(subject, NatsSubjectTaxonomy.GrammarLimits())
	compiled, patternErr := SubjectPermissionPatternTryParse(pattern, NatsSubjectTaxonomy.GrammarLimits())
	if concreteErr != SubjectGrammarErrorNone || patternErr != SubjectGrammarErrorNone {
		panic("corpus pattern or subject is not bounded grammar: " + pattern + " / " + subject)
	}

	return compiled.Matches(concrete)
}

func TestWriteAuthorityOverTheClosedSubjectCorpusIsDisjointAcrossKinds(t *testing.T) {
	for _, subject := range controlSubjectCorpus(t) {
		publisherKinds := map[NatsControlAccountKind]struct{}{}
		for _, scope := range allTestScopes(t) {
			for _, pattern := range scope.Publish {
				if corpusMatches(pattern, subject) {
					publisherKinds[scope.Kind] = struct{}{}
					break
				}
			}
		}

		if len(publisherKinds) != 1 {
			t.Fatalf("exactly one account kind may publish %q, but %d do (%v)",
				subject, len(publisherKinds), publisherKinds)
		}
	}
}

func TestReadOnlyAndBreakGlassKindsHoldNoWriteGrants(t *testing.T) {
	for _, scope := range allTestScopes(t) {
		switch scope.Kind {
		case NatsControlAccountKindGlobalDirectoryReadService,
			NatsControlAccountKindReadOnlyMonitoring,
			NatsControlAccountKindBreakGlassRecovery:
			if len(scope.Publish) != 0 {
				t.Fatalf("kind %v holds write grants", scope.Kind)
			}
		}
	}

	breakGlass := mustScope(t, NatsControlAccountKindBreakGlassRecovery, "", "")
	if len(breakGlass.Publish) != 0 || len(breakGlass.Subscribe) != 0 {
		t.Fatal("break-glass scope holds standing grants")
	}
}

func TestRegionalScopesArePinnedToExactlyOneRegion(t *testing.T) {
	gru := mustScope(t, NatsControlAccountKindRegionalController, "gru", "host/gru/agent-07")
	sfo := mustScope(t, NatsControlAccountKindRegionalController, "sfo", "host/sfo/agent-07")

	patterns := append(append([]string{}, gru.Publish...), gru.Subscribe...)
	for _, pattern := range patterns {
		pinned := strings.HasPrefix(pattern, "ts.orch.v1.gru.") || strings.HasPrefix(pattern, "ts.orch.v1.global.")
		if !pinned {
			t.Fatalf("the GRU controller scope must stay pinned to GRU or the global scope: %q", pattern)
		}
	}

	for _, subject := range controlSubjectCorpus(t) {
		if !strings.HasPrefix(subject, "ts.orch.v1.sfo.") {
			continue
		}

		for _, pattern := range gru.Publish {
			if corpusMatches(pattern, subject) {
				t.Fatalf("the GRU controller must not be able to write the SFO subject %q", subject)
			}
		}
	}

	for _, pattern := range sfo.Publish {
		if corpusMatches(pattern, "ts.orch.v1.sfo.desired.gitops") {
			return
		}
	}

	t.Fatal("the SFO controller must be able to write its own CellSpec subject")
}

func TestHostAgentScopesUseTheFixedAgentHashNeverTheRawIdentity(t *testing.T) {
	agent := mustScope(t, NatsControlAccountKindHostAgent, "gru", gruAgent)
	token := must(t, func() (string, error) { return NatsSubjectTaxonomy.HostAgentSubjectToken(gruAgent) })

	if agent.AgentHash != token || agent.RegionToken != "gru" {
		t.Fatalf("agent scope pinning = %q / %q", agent.AgentHash, agent.RegionToken)
	}

	patterns := append(append([]string{}, agent.Publish...), agent.Subscribe...)
	for _, pattern := range patterns {
		if !strings.Contains(pattern, token) {
			t.Fatalf("agent grant %q must carry the hash token", pattern)
		}

		if strings.Contains(pattern, gruAgent) {
			t.Fatalf("agent grant %q must not carry the raw identity", pattern)
		}
	}

	if len(agent.Publish) != 2 ||
		!slices.Contains(agent.Publish, "ts.orch.v1.gru.agent."+token+".observation.>") ||
		!slices.Contains(agent.Publish, "ts.orch.v1.gru.agent."+token+".ack.>") {
		t.Fatalf("agent publish grants = %v", agent.Publish)
	}

	if len(agent.Subscribe) != 1 || agent.Subscribe[0] != "ts.orch.v1.gru.agent."+token+".command.>" {
		t.Fatalf("agent subscribe grants = %v", agent.Subscribe)
	}

	// The regional controller commands the agent; the agent answers on its own hashed branch.
	controller := mustScope(t, NatsControlAccountKindRegionalController, "gru", gruAgent)
	if !slices.Contains(controller.Publish, "ts.orch.v1.gru.agent."+token+".command.>") {
		t.Fatalf("controller publish grants = %v", controller.Publish)
	}

	if !slices.Contains(controller.Subscribe, "ts.orch.v1.gru.agent."+token+".observation.>") {
		t.Fatalf("controller subscribe grants = %v", controller.Subscribe)
	}
}

func TestScopeCreationFailsClosedOnMismatchedScopeInputs(t *testing.T) {
	failing := []struct {
		kind          NatsControlAccountKind
		regionToken   string
		agentIdentity string
	}{
		{NatsControlAccountKindRegionalController, "", ""},
		{NatsControlAccountKindRegionalController, "GRU", ""},
		{NatsControlAccountKindRegionalController, "global", ""},
		{NatsControlAccountKindHostAgent, "gru", ""},
		{NatsControlAccountKindGlobalAuthority, "gru", ""},
		{NatsControlAccountKindInfrastructureAdministration, "", "host/gru/agent-07"},
	}

	for _, testCase := range failing {
		if _, err := NatsControlAccountScopeCreate(testCase.kind, testCase.regionToken, testCase.agentIdentity); err == nil {
			t.Fatalf("scope creation must fail for %v %q %q", testCase.kind, testCase.regionToken, testCase.agentIdentity)
		}
	}

	if _, err := NatsControlAccountScopeCreate(NatsControlAccountKindUnspecified, "", ""); err == nil {
		t.Fatal("unspecified kind must fail")
	}
}
