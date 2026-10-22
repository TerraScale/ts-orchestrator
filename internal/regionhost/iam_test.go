package regionhost

import (
	"strings"
	"testing"
)

func TestSameRuleIgnoresOrderOnly(t *testing.T) {
	live := "ANY {instance.compartment.id = 'gru', instance.compartment.id = 'sjc', instance.compartment.id = 'fra'}"
	if !sameRule(live, []string{"fra", "gru", "sjc"}) {
		t.Error("the live rule in another order is a change")
	}
	for _, ids := range [][]string{{"fra", "gru"}, {"fra", "gru", "sjc", "nrt"}} {
		if sameRule(live, ids) {
			t.Errorf("rule for %v is unchanged", ids)
		}
	}
	if sameRule("ANY {instance.compartment.id = 'gru', resource.type = 'x'}", []string{"gru"}) {
		t.Error("a rule with a foreign term is unchanged")
	}
	if got := matchingRule([]string{"a", "b"}); got != "ANY {instance.compartment.id = 'a', instance.compartment.id = 'b'}" {
		t.Errorf("rule %s", got)
	}
}

func TestStatementsAddOneJoinSecretPerRegion(t *testing.T) {
	s := statements([]string{"sjc", "gru"})
	if len(s) != 8 || !strings.HasSuffix(s[6], "target.secret.name = 'ts-orch-join-gru'}") || !strings.HasSuffix(s[7], "'ts-orch-join-sjc'}") {
		t.Fatalf("statements %q", s)
	}
	if !strings.Contains(s[3], "target.secret.name = 'ts-orch-mesh-key'") || !strings.Contains(s[6], "manage secret-family in compartment id "+gruCompartment+" where all {target.vault.id = '"+gruVault+"'") {
		t.Fatalf("statements %q", s)
	}
}
