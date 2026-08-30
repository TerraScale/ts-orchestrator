// Port of tests/TerraScale.Orchestrator.Protocol.Tests/ProtocolManifestTests.cs.
package protocol

import (
	"slices"
	"sort"
	"strings"
	"testing"
)

var goalFamilies = []string{
	"ts.orch.v2.global.desired.>",
	"ts.orch.v2.global.release.>",
	"ts.orch.v2.global.query.>",
	"ts.orch.v2.<region>.desired.>",
	"ts.orch.v2.<region>.command.>",
	"ts.orch.v2.<region>.observation.>",
	"ts.orch.v2.<region>.operation.>",
	"ts.orch.v2.<region>.query.>",
	"ts.orch.v2.<region>.audit.>",
	"ts.orch.v2.<region>.agent.<agent-hash>.>",
}

func TestTheManifestPinsExactlyTheFreshV2Root(t *testing.T) {
	manifest := ProtocolManifestLoaded()

	if manifest.Root != "ts.orch.v2" || manifest.Root != NatsSubjectTaxonomy.Root() {
		t.Fatalf("manifest root = %q", manifest.Root)
	}

	if manifest.Version != "v2" {
		t.Fatalf("manifest version = %q", manifest.Version)
	}

	if len(manifest.SupersededRoots) != 1 || manifest.SupersededRoots[0] != "ts.orch.v1" {
		t.Fatalf("superseded roots = %v", manifest.SupersededRoots)
	}

	if len(manifest.ReservedRegionTokens) != 1 || manifest.ReservedRegionTokens[0] != "global" {
		t.Fatalf("reserved region tokens = %v", manifest.ReservedRegionTokens)
	}
}

func TestTheTaxonomyAndTheManifestAgreeInBothDirections(t *testing.T) {
	if violations := NatsSubjectTaxonomy.ManifestValidationViolations(); len(violations) != 0 {
		t.Fatalf("violations = %v", violations)
	}

	families := NatsSubjectTaxonomy.Families()
	if len(families) != 10 {
		t.Fatalf("family count = %d", len(families))
	}

	manifestPatterns := map[string]struct{}{}
	for _, family := range ProtocolManifestLoaded().SubjectFamilies {
		manifestPatterns[family.Pattern] = struct{}{}
	}

	for _, pattern := range goalFamilies {
		if _, present := manifestPatterns[pattern]; !present {
			t.Fatalf("manifest is missing the goal family %q", pattern)
		}
	}

	for pattern := range manifestPatterns {
		if !slices.Contains(goalFamilies, pattern) {
			t.Fatalf("manifest declares the unknown family %q", pattern)
		}
	}
}

func TestEveryGoalFamilyIsPresentAndTheSetIsClosed(t *testing.T) {
	families := NatsSubjectTaxonomy.Families()
	patterns := make([]string, 0, len(families))
	globalFamilies := []string{}
	regionalFamilies := []string{}
	for _, family := range families {
		patterns = append(patterns, family.Pattern)
		if family.Scope == ProtocolSubjectFamilyScopeGlobal {
			globalFamilies = append(globalFamilies, family.Family)
		} else if family.Scope == ProtocolSubjectFamilyScopeRegional {
			regionalFamilies = append(regionalFamilies, family.Family)
		}
	}

	sort.Strings(patterns)
	expected := append([]string(nil), goalFamilies...)
	sort.Strings(expected)
	if len(patterns) != len(expected) {
		t.Fatalf("family set differs: %v vs %v", patterns, expected)
	}

	for index := range patterns {
		if patterns[index] != expected[index] {
			t.Fatalf("family set differs at %d: %q vs %q", index, patterns[index], expected[index])
		}
	}

	sort.Strings(globalFamilies)
	if len(globalFamilies) != 3 || globalFamilies[0] != "desired" || globalFamilies[1] != "query" || globalFamilies[2] != "release" {
		t.Fatalf("global families = %v", globalFamilies)
	}

	sort.Strings(regionalFamilies)
	wantRegional := []string{"agent", "audit", "command", "desired", "observation", "operation", "query"}
	if len(regionalFamilies) != len(wantRegional) {
		t.Fatalf("regional families = %v", regionalFamilies)
	}

	for index := range regionalFamilies {
		if regionalFamilies[index] != wantRegional[index] {
			t.Fatalf("regional families = %v", regionalFamilies)
		}
	}

	for _, family := range families {
		if family.Scope == ProtocolSubjectFamilyScopeRegional {
			if !strings.HasPrefix(family.Pattern, "ts.orch.v2.<region>.") {
				t.Fatalf("regional family %q must carry the region placeholder", family.Family)
			}
		}
	}
}

func TestEveryMaterializedManifestFamilyIsAClosedV2Permission(t *testing.T) {
	agentHash, err := NatsSubjectTaxonomy.HostAgentSubjectToken("host/gru/agent-07")
	if err != nil {
		t.Fatalf("agent hash failed: %v", err)
	}

	for _, family := range NatsSubjectTaxonomy.Families() {
		pattern := strings.ReplaceAll(strings.ReplaceAll(family.Pattern,
			NatsSubjectTaxonomy.RegionPlaceholderToken(), "gru"),
			NatsSubjectTaxonomy.AgentHashPlaceholderToken(), agentHash)

		ok, err := NatsSubjectTaxonomy.TryValidatePermissionPattern(pattern)
		if !ok || err != NatsSubjectPermissionErrorNone {
			t.Fatalf("materialized family pattern %q is not a closed v2 permission: %v", pattern, err)
		}
	}
}

func TestNoManifestSurfaceSharesTheSupersededV1Root(t *testing.T) {
	manifest := ProtocolManifestLoaded()

	for _, family := range manifest.SubjectFamilies {
		if strings.HasPrefix(family.Pattern, NatsSubjectTaxonomy.SupersededRoot()+".") {
			t.Fatalf("family %q lives under the v1 root", family.Pattern)
		}

		if !strings.HasPrefix(family.Pattern, NatsSubjectTaxonomy.Root()+".") {
			t.Fatalf("family %q does not live under the v2 root", family.Pattern)
		}
	}

	for _, grants := range manifest.AccountKinds {
		patterns := append(append([]string{}, grants.Publish...), grants.Subscribe...)
		for _, pattern := range patterns {
			if strings.HasPrefix(pattern, NatsSubjectTaxonomy.SupersededRoot()+".") {
				t.Fatalf("account kind %q holds a v1 permission", grants.Kind)
			}
		}
	}
}
