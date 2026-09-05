package natspolicy

import (
	"slices"
	"sort"
	"strings"
	"testing"
)

var goalFamilies = []string{
	"ts.orch.v1.global.desired.>",
	"ts.orch.v1.global.release.>",
	"ts.orch.v1.global.query.>",
	"ts.orch.v1.<region>.desired.>",
	"ts.orch.v1.<region>.command.>",
	"ts.orch.v1.<region>.observation.>",
	"ts.orch.v1.<region>.operation.>",
	"ts.orch.v1.<region>.query.>",
	"ts.orch.v1.<region>.audit.>",
	"ts.orch.v1.<region>.agent.<agent-hash>.>",
}

func TestTheManifestPinsExactlyTheFreshV1Root(t *testing.T) {
	manifest := ProtocolManifestLoaded()

	if manifest.Root != "ts.orch.v1" || manifest.Root != NatsSubjectTaxonomy.Root() {
		t.Fatalf("manifest root = %q", manifest.Root)
	}

	if manifest.Version != "v1" {
		t.Fatalf("manifest version = %q", manifest.Version)
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
			if !strings.HasPrefix(family.Pattern, "ts.orch.v1.<region>.") {
				t.Fatalf("regional family %q must carry the region placeholder", family.Family)
			}
		}
	}
}

func TestEveryMaterializedManifestFamilyIsAClosedV1Permission(t *testing.T) {
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
			t.Fatalf("materialized family pattern %q is not a closed v1 permission: %v", pattern, err)
		}
	}
}
