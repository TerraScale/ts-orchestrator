// Port of tests/TerraScale.Orchestrator.Protocol.Tests/MessagingSemanticClassesTests.cs.
// The landed-subject and landed-store drift bindings against NatsTopology and
// GlobalNatsTopology are skipped until the control package is ported; the
// taxonomy-composed equivalents of every landed subject shape are covered here.
package protocol

import (
	"strings"
	"testing"
)

func TestEveryLandedSubjectShapeMapsToExactlyOneDeclaredSemanticClass(t *testing.T) {
	cases := []struct {
		subject string
		want    MessagingSemanticClass
	}{
		{mustT(t, func() (string, error) { return NatsSubjectTaxonomy.CellSpecSubject("gru") }), MessagingSemanticClassAuthoritativeJournal},
		{mustT(t, func() (string, error) { return NatsSubjectTaxonomy.ControllerHealthSubject("gru") }), MessagingSemanticClassLossy},
		{mustT(t, func() (string, error) {
			return NatsSubjectTaxonomy.ControllerInstanceHealthSubject("gru", "controller-1")
		}), MessagingSemanticClassLossy},
		{mustT(t, func() (string, error) { return NatsSubjectTaxonomy.ControllerStatusSubject("gru") }), MessagingSemanticClassLossy},
		{mustT(t, func() (string, error) { return NatsSubjectTaxonomy.ControllerMembersSubject("gru") }), MessagingSemanticClassLossy},
		{mustT(t, func() (string, error) { return NatsSubjectTaxonomy.DirectDeliverySubject("gru") }), MessagingSemanticClassLossy},
		{mustT(t, func() (string, error) { return NatsSubjectTaxonomy.OperationJournalCreateSubject("gru") }), MessagingSemanticClassLossy},
		{mustT(t, func() (string, error) { return NatsSubjectTaxonomy.OperationJournalUpdateSubject("gru") }), MessagingSemanticClassLossy},
		{mustT(t, func() (string, error) {
			return NatsSubjectTaxonomy.OperationJournalReplySubject("gru", "UABC", strings.Repeat("a", 32))
		}), MessagingSemanticClassLossy},
		{mustT(t, func() (string, error) {
			return NatsSubjectTaxonomy.RuntimeLifecycleJournalReplySubject("gru", "UABC", strings.Repeat("b", 32))
		}), MessagingSemanticClassLossy},
		{mustT(t, func() (string, error) { return NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject("gru", "read") }), MessagingSemanticClassLossy},
		{mustT(t, func() (string, error) { return NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1") }), MessagingSemanticClassReplayable},
		{NatsSubjectTaxonomy.GlobalDirectoryQuerySubject(), MessagingSemanticClassLossy},
		{NatsSubjectTaxonomy.CiForgejoTriggerSubject(), MessagingSemanticClassWorkQueue},
		{NatsSubjectTaxonomy.CiRuntimeProofSubject(), MessagingSemanticClassReplayable},
		{mustT(t, func() (string, error) { return NatsSubjectTaxonomy.GlobalCellSpecSubject("sfo") }), MessagingSemanticClassAuthoritativeJournal},
		{mustT(t, func() (string, error) {
			return NatsSubjectTaxonomy.HostAgentCommandSubject("gru", "host/gru/agent-07", "start")
		}), MessagingSemanticClassWorkQueue},
	}

	for _, testCase := range cases {
		classified, _, ok := MessagingSemanticClasses.TryClassifySubject(testCase.subject)
		if !ok {
			t.Fatalf("the subject %q must be classified", testCase.subject)
		}

		if classified != testCase.want {
			t.Fatalf("subject %q classified as %v, want %v", testCase.subject, classified, testCase.want)
		}
	}
}

func TestUnknownAndForeignSubjectsFailClosedInsteadOfGuessingAClass(t *testing.T) {
	for _, subject := range []string{
		"ts.orch.v2.gru.unknown.channel",
		"ts.product.v1.queue",
		"$JS.API.STREAM.INFO",
		"",
	} {
		if _, _, ok := MessagingSemanticClasses.TryClassifySubject(subject); ok {
			t.Fatalf("subject %q must not be classified", subject)
		}
	}
}

func TestReservedNamespacesCarryTheirIntendedSemanticClass(t *testing.T) {
	if agent, _, ok := MessagingSemanticClasses.TryClassifySubject(
		mustT(t, func() (string, error) {
			return NatsSubjectTaxonomy.HostAgentCommandSubject("gru", "host/gru/agent-07", "start")
		})); !ok ||
		agent != MessagingSemanticClassWorkQueue {
		t.Fatalf("agent class = %v", agent)
	}

	if audit, _, ok := MessagingSemanticClasses.TryClassifySubject(
		mustT(t, func() (string, error) { return NatsSubjectTaxonomy.RegionalRoot("gru") }) + ".audit.entry"); !ok ||
		audit != MessagingSemanticClassAuthoritativeJournal {
		t.Fatalf("audit class = %v", audit)
	}
}

func TestAuthoritativeJournalStoresAreNeverClassifiedAsLossyOrSnapshot(t *testing.T) {
	for _, rule := range MessagingSemanticClasses.StoreRules() {
		if rule.SemanticClass == MessagingSemanticClassAuthoritativeJournal {
			if strings.Contains(rule.LossMeaning, "rebuild from hints") {
				t.Fatalf("authoritative store %q claims to rebuild from hints", rule.StoreIdentity)
			}
		}
	}

	for _, rule := range MessagingSemanticClasses.StoreRules() {
		if rule.StoreIdentity == "ORCH_OPERATIONS" {
			if rule.SemanticClass != MessagingSemanticClassAuthoritativeJournal {
				t.Fatalf("ORCH_OPERATIONS class = %v", rule.SemanticClass)
			}

			return
		}
	}

	t.Fatal("ORCH_OPERATIONS store rule missing")
}

func TestSubjectPatternsCompileAndAgreeWithTheNamespaceTaxonomy(t *testing.T) {
	for _, rule := range MessagingSemanticClasses.SubjectRules() {
		if !strings.Contains(rule.SubjectPattern, "*") && !strings.HasSuffix(rule.SubjectPattern, ">") {
			if NatsSubjectTaxonomy.Classify(rule.SubjectPattern) != rule.Namespace {
				t.Fatalf("rule %q classified as %v, want %v",
					rule.SubjectPattern, NatsSubjectTaxonomy.Classify(rule.SubjectPattern), rule.Namespace)
			}
		}
	}
}
