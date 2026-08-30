// Port of tests/TerraScale.Orchestrator.Protocol.Tests/NatsSubjectTaxonomyTests.cs.
// The tests that pin the taxonomy against the control-plane topologies
// (NatsTopology, GlobalNatsTopology, RuntimeLifecycleNatsProtocol) are skipped
// until those areas are ported; the taxonomy sides of those checks are covered
// by the rehomed-subject and host-agent tests below.
package protocol

import (
	"strings"
	"testing"
)

const testAgentIdentity = "host/gru/agent-07"

func TestTheControlRootIsExactlyTheFreshV2ProtocolRoot(t *testing.T) {
	if NatsSubjectTaxonomy.Root() != "ts.orch.v2" {
		t.Fatal("root mismatch")
	}

	if NatsSubjectTaxonomy.SupersededRoot() != "ts.orch.v1" {
		t.Fatal("superseded root mismatch")
	}

	if NatsSubjectTaxonomy.GlobalRoot() != "ts.orch.v2.global" {
		t.Fatal("global root mismatch")
	}

	if root, err := NatsSubjectTaxonomy.RegionalRoot("gru"); err != nil || root != "ts.orch.v2.gru" {
		t.Fatalf("regional root = %q, err = %v", root, err)
	}

	if root, err := NatsSubjectTaxonomy.RegionalRootForRegionCode("GRU"); err != nil || root != "ts.orch.v2.gru" {
		t.Fatalf("regional root for RegionCode = %q, err = %v", root, err)
	}
}

func TestRehomedBridgeSubjectsLandInsideTheClosedV2Families(t *testing.T) {
	if subject, err := NatsSubjectTaxonomy.OperationJournalCreateSubject("gru"); err != nil ||
		subject != "ts.orch.v2.gru.command.journal.create" {
		t.Fatalf("create subject = %q, err = %v", subject, err)
	}

	if subject, err := NatsSubjectTaxonomy.OperationJournalUpdateSubject("gru"); err != nil ||
		subject != "ts.orch.v2.gru.command.journal.update" {
		t.Fatalf("update subject = %q, err = %v", subject, err)
	}

	if subject, err := NatsSubjectTaxonomy.OperationJournalReplySubject("gru", "UABC", strings.Repeat("a", 32)); err != nil ||
		subject != "ts.orch.v2.gru.command.journal.reply.UABC."+strings.Repeat("a", 32) {
		t.Fatalf("reply subject = %q, err = %v", subject, err)
	}

	if subject, err := NatsSubjectTaxonomy.ControllerInboxPrefix("gru", "UABC"); err != nil ||
		subject != "ts.orch.v2.gru.command.reply.UABC" {
		t.Fatalf("inbox prefix = %q, err = %v", subject, err)
	}

	if subject, err := NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1"); err != nil ||
		subject != "ts.orch.v2.gru.observation.runtime.started.controller-1" {
		t.Fatalf("startup subject = %q, err = %v", subject, err)
	}

	if subject, err := NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject("gru", "read"); err != nil ||
		subject != "ts.orch.v2.gru.command.runtime-lifecycle.read" {
		t.Fatalf("lifecycle subject = %q, err = %v", subject, err)
	}

	subjects := []struct {
		value    string
		expected NatsSubjectNamespace
	}{
		{must(t, func() (string, error) { return NatsSubjectTaxonomy.OperationJournalCreateSubject("gru") }), NatsSubjectNamespaceRegionalControl},
		{must(t, func() (string, error) { return NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject("gru", "read") }), NatsSubjectNamespaceRegionalControl},
		{must(t, func() (string, error) { return NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1") }), NatsSubjectNamespaceRegionalControl},
		{must(t, func() (string, error) { return NatsSubjectTaxonomy.ControllerInboxPrefix("gru", "UABC") }), NatsSubjectNamespaceRegionalControl},
	}

	for _, subject := range subjects {
		if NatsSubjectTaxonomy.Classify(subject.value) != subject.expected {
			t.Fatalf("subject %q classified as %v", subject.value, NatsSubjectTaxonomy.Classify(subject.value))
		}

		if ok, err := NatsSubjectTaxonomy.TryAdmitSubject(subject.value); !ok || err != NatsSubjectAdmissionErrorNone {
			t.Fatalf("rehomed subject %q must be admissible: %v", subject.value, err)
		}
	}
}

func must(t *testing.T, compose func() (string, error)) string {
	t.Helper()
	value, err := compose()
	if err != nil {
		t.Fatalf("subject composition failed: %v", err)
	}

	return value
}

func TestHostAgentSubjectsUseTheFixedHashOfTheAdmittedIdentity(t *testing.T) {
	token, err := NatsSubjectTaxonomy.HostAgentSubjectToken(testAgentIdentity)
	if err != nil {
		t.Fatalf("token failed: %v", err)
	}

	if len(token) != NatsSubjectTaxonomy.AgentHashTokenLength() {
		t.Fatalf("token length = %d", len(token))
	}

	for index := 0; index < len(token); index++ {
		character := token[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			t.Fatalf("token %q is not lowercase hex", token)
		}
	}

	otherToken, _ := NatsSubjectTaxonomy.HostAgentSubjectToken("host/gru/agent-08")
	if otherToken == token {
		t.Fatal("identities must hash to distinct tokens")
	}

	root := must(t, func() (string, error) { return NatsSubjectTaxonomy.HostAgentSubjectRoot("gru", testAgentIdentity) })
	if root != "ts.orch.v2.gru.agent."+token {
		t.Fatalf("agent root = %q", root)
	}

	if strings.Contains(root, testAgentIdentity) {
		t.Fatal("agent root must not contain the raw identity")
	}

	if subject, err := NatsSubjectTaxonomy.HostAgentCommandSubject("gru", testAgentIdentity, "start"); err != nil ||
		subject != root+".command.start" {
		t.Fatalf("command subject = %q", subject)
	}

	if subject, err := NatsSubjectTaxonomy.HostAgentObservationSubject("gru", testAgentIdentity, "heartbeat"); err != nil ||
		subject != root+".observation.heartbeat" {
		t.Fatalf("observation subject = %q", subject)
	}

	if subject, err := NatsSubjectTaxonomy.HostAgentAcknowledgementSubject("gru", testAgentIdentity, "42"); err != nil ||
		subject != root+".ack.42" {
		t.Fatalf("acknowledgement subject = %q", subject)
	}

	if NatsSubjectTaxonomy.Classify(root) != NatsSubjectNamespaceAgent {
		t.Fatalf("agent root classified as %v", NatsSubjectTaxonomy.Classify(root))
	}

	if _, err := NatsSubjectTaxonomy.HostAgentIdentityHash("agent with space"); err == nil {
		t.Fatal("identity with whitespace must be rejected")
	}

	if _, err := NatsSubjectTaxonomy.HostAgentIdentityHash(strings.Repeat("a", 513)); err == nil {
		t.Fatal("overlong identity must be rejected")
	}
}

func TestRegisteredRegionCodesAndSubjectTokensAreBijectiveAndExact(t *testing.T) {
	for _, pair := range [][2]string{{"GRU", "gru"}, {"SFO", "sfo"}, {"FRA", "fra"}} {
		if mapped, ok := NatsSubjectTaxonomy.TryMapRegionCodeToSubjectToken(pair[0]); !ok || mapped != pair[1] {
			t.Fatalf("RegionCode %q mapped to %q", pair[0], mapped)
		}

		if code, ok := NatsSubjectTaxonomy.TryMapSubjectTokenToRegionCode(pair[1]); !ok || code != pair[0] {
			t.Fatalf("token %q mapped to %q", pair[1], code)
		}

		if token, err := NatsSubjectTaxonomy.SubjectTokenForRegion(pair[0]); err != nil || token != pair[1] {
			t.Fatalf("subject token for %q = %q", pair[0], token)
		}

		if code, err := NatsSubjectTaxonomy.RegionCodeFromSubjectToken(pair[1]); err != nil || code != pair[0] {
			t.Fatalf("RegionCode for %q = %q", pair[1], code)
		}
	}

	for _, value := range []string{"", "gru", "Gru", " GRU", "GRU ", "GR", "GRUU", "IAD", "US1", "G-U", "G.U", "GRÜ", "GLOBAL", "G\x00U"} {
		if mapped, ok := NatsSubjectTaxonomy.TryMapRegionCodeToSubjectToken(value); ok || mapped != "" {
			t.Fatalf("RegionCode %q must be refused", value)
		}
	}

	for _, value := range []string{"", "GRU", "Gru", " gru", "gru ", "gr", "gruu", "iad", "us1", "g-u", "g.u", "grü", "global", "g\x00u"} {
		if code, ok := NatsSubjectTaxonomy.TryMapSubjectTokenToRegionCode(value); ok || code != "" {
			t.Fatalf("subject token %q must be refused", value)
		}
	}

	if _, err := NatsSubjectTaxonomy.SubjectTokenForRegion("IAD"); err == nil {
		t.Fatal("unregistered RegionCode must be refused")
	}

	if _, err := NatsSubjectTaxonomy.RegionCodeFromSubjectToken("global"); err == nil {
		t.Fatal("reserved scope token must be refused as a RegionCode")
	}

	if _, err := NatsSubjectTaxonomy.RegionalRootForRegionCode("US1"); err == nil {
		t.Fatal("unregistered RegionCode must be refused in the root composer")
	}

	// Raw subject-token APIs preserve established NATS identifiers. They do not
	// admit RegionCode values.
	if root, err := NatsSubjectTaxonomy.RegionalRoot("us1"); err != nil || root != "ts.orch.v2.us1" {
		t.Fatalf("raw token root = %q, err = %v", root, err)
	}

	if _, err := NatsSubjectTaxonomy.RegionalRoot("global"); err == nil {
		t.Fatal("reserved scope token must be refused in the root composer")
	}

	if _, err := NatsSubjectTaxonomy.GlobalCellSpecSubject("global"); err == nil {
		t.Fatal("reserved scope token must be refused in the global CellSpec composer")
	}
}

func TestClassificationSeparatesEveryNamespaceOfTheClosedTaxonomy(t *testing.T) {
	cases := []struct {
		subject string
		want    NatsSubjectNamespace
	}{
		{must(t, func() (string, error) { return NatsSubjectTaxonomy.GlobalCellSpecSubject("gru") }), NatsSubjectNamespaceGlobalAuthority},
		{NatsSubjectTaxonomy.GlobalRoot() + ".release.accepted.r7", NatsSubjectNamespaceGlobalAuthority},
		{NatsSubjectTaxonomy.GlobalRoot() + ".query.health", NatsSubjectNamespaceGlobalAuthority},
		{NatsSubjectTaxonomy.GlobalDirectoryQuerySubject(), NatsSubjectNamespaceGlobalDirectory},
		{must(t, func() (string, error) { return NatsSubjectTaxonomy.CellSpecSubject("gru") }), NatsSubjectNamespaceRegionalControl},
		{must(t, func() (string, error) { return NatsSubjectTaxonomy.ControllerStatusSubject("sfo") }), NatsSubjectNamespaceRegionalControl},
		{must(t, func() (string, error) { return NatsSubjectTaxonomy.DirectDeliverySubject("fra") }), NatsSubjectNamespaceRegionalControl},
		{must(t, func() (string, error) { return NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1") }), NatsSubjectNamespaceRegionalControl},
		{must(t, func() (string, error) { return NatsSubjectTaxonomy.RegionalRoot("gru") }) + ".observation.host.pressure", NatsSubjectNamespaceRegionalControl},
		{must(t, func() (string, error) { return NatsSubjectTaxonomy.OperationJournalCreateSubject("gru") }), NatsSubjectNamespaceRegionalControl},
		{must(t, func() (string, error) { return NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject("gru", "read") }), NatsSubjectNamespaceRegionalControl},
		{must(t, func() (string, error) { return NatsSubjectTaxonomy.RegionalRoot("gru") }) + ".operation.created", NatsSubjectNamespaceOperations},
		{NatsSubjectTaxonomy.CiForgejoTriggerSubject(), NatsSubjectNamespaceContinuousIntegration},
		{NatsSubjectTaxonomy.CiRuntimeProofSubject(), NatsSubjectNamespaceContinuousIntegration},
		{NatsSubjectTaxonomy.CiJobSubjectPrefix() + ".trusted-build.abcd", NatsSubjectNamespaceContinuousIntegration},
		{must(t, func() (string, error) { return NatsSubjectTaxonomy.HostAgentSubjectRoot("gru", testAgentIdentity) }), NatsSubjectNamespaceAgent},
		{must(t, func() (string, error) { return NatsSubjectTaxonomy.RegionalRoot("gru") }) + ".audit.event.7", NatsSubjectNamespaceAudit},
		{"ts.product.v1.queue.default", NatsSubjectNamespaceProductPlane},
		{"$JS.API.STREAM.INFO.CELL_SPEC", NatsSubjectNamespacePlatformReserved},
		{"_INBOX.abcd.1234", NatsSubjectNamespacePlatformReserved},
		{"$SRV.INFO.terrascale_orchestrator_gru", NatsSubjectNamespacePlatformReserved},
	}

	for _, testCase := range cases {
		if NatsSubjectTaxonomy.Classify(testCase.subject) != testCase.want {
			t.Fatalf("subject %q classified as %v", testCase.subject, NatsSubjectTaxonomy.Classify(testCase.subject))
		}
	}
}

func TestClassificationFailsClosedOnUnknownAndSupersededShapes(t *testing.T) {
	unknown := []string{
		"ts.orch.v1.gru.desired.gitops",
		"ts.orch.v1.global.query.cells",
		"ts.orch.v1.gru.unknown.channel",
		"ts.orch.v2.gru.unknown.channel",
		"ts.orch.v2.gru.event.runtime.started.controller-1",
		"ts.orch.v2.gru.internal.operation-journal.create",
		"ts.orch.v2.global.ci.forgejo",
		"ts.orch.v2.global.journal.ledger",
		"ts.orch.v2.global",
		"ts.other.v1.gru.query.health",
		"",
	}

	for _, subject := range unknown {
		if NatsSubjectTaxonomy.Classify(subject) != NatsSubjectNamespaceUnknown {
			t.Fatalf("subject %q must not classify into the v2 taxonomy", subject)
		}
	}
}

func TestProductPlaneAndUnknownNamespacesAreNotControlNamespaces(t *testing.T) {
	if NatsSubjectTaxonomy.IsControlNamespace(NatsSubjectNamespaceProductPlane) ||
		NatsSubjectTaxonomy.IsControlNamespace(NatsSubjectNamespaceUnknown) ||
		NatsSubjectTaxonomy.IsControlNamespace(NatsSubjectNamespacePlatformReserved) {
		t.Fatal("product, unknown, and platform namespaces are not control namespaces")
	}

	for _, ns := range []NatsSubjectNamespace{
		NatsSubjectNamespaceGlobalAuthority,
		NatsSubjectNamespaceGlobalDirectory,
		NatsSubjectNamespaceRegionalControl,
		NatsSubjectNamespaceAgent,
		NatsSubjectNamespaceContinuousIntegration,
		NatsSubjectNamespaceOperations,
		NatsSubjectNamespaceAudit,
	} {
		if !NatsSubjectTaxonomy.IsControlNamespace(ns) {
			t.Fatalf("namespace %v must be a control namespace", ns)
		}
	}
}

func TestSubjectBuildersFailClosedOnInvalidInput(t *testing.T) {
	if _, err := NatsSubjectTaxonomy.RegionalRoot("GRU"); err == nil {
		t.Fatal("uppercase cell must be refused")
	}

	if _, err := NatsSubjectTaxonomy.RegionalRoot("-gru-"); err == nil {
		t.Fatal("dashed cell must be refused")
	}

	if _, err := NatsSubjectTaxonomy.GlobalCellSpecSubject("gru cell"); err == nil {
		t.Fatal("cell with space must be refused")
	}

	if _, err := NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject("gru", "bad operation"); err == nil {
		t.Fatal("operation with space must be refused")
	}

	if _, err := NatsSubjectTaxonomy.RuntimeLifecycleJournalReplySubject("gru", "id", "not-a-nonce"); err == nil {
		t.Fatal("malformed nonce must be refused")
	}

	if _, err := NatsSubjectTaxonomy.ControllerInboxPrefix("gru", ""); err == nil {
		t.Fatal("empty public key must be refused")
	}
}

func TestNoWildcardPermissionMayCrossARegionBoundary(t *testing.T) {
	rejected := []struct {
		pattern string
		want    NatsSubjectPermissionError
	}{
		{"ts.orch.v2.*.desired.>", NatsSubjectPermissionErrorWildcardInScopeToken},
		{"ts.orch.v2.*.query.>", NatsSubjectPermissionErrorWildcardInScopeToken},
		{"ts.orch.v2.>", NatsSubjectPermissionErrorWildcardInScopeToken},
		{"ts.orch.v2.*.agent.>", NatsSubjectPermissionErrorWildcardInScopeToken},
		{"ts.orch.v2.gru.>", NatsSubjectPermissionErrorWildcardInFamilyToken},
		{"ts.orch.v2.gru.*.>", NatsSubjectPermissionErrorWildcardInFamilyToken},
		{"ts.orch.v2.global.>", NatsSubjectPermissionErrorWildcardInFamilyToken},
		{"ts.orch.v2.gru.event.>", NatsSubjectPermissionErrorUnknownFamily},
		{"ts.orch.v2.gru.internal.>", NatsSubjectPermissionErrorUnknownFamily},
		{"ts.orch.v2.global.ci.>", NatsSubjectPermissionErrorUnknownFamily},
		{"ts.orch.v2.GRU.desired.>", NatsSubjectPermissionErrorInvalidRegionToken},
		{"ts.orch.v2.gru.agent.*.command.>", NatsSubjectPermissionErrorInvalidAgentHashToken},
		{"ts.orch.v2.gru.agent.>", NatsSubjectPermissionErrorInvalidAgentHashToken},
		{"ts.orch.v2.gru.agent.not-a-fixed-hash.command.>", NatsSubjectPermissionErrorInvalidAgentHashToken},
		{"ts.orch.v1.gru.desired.>", NatsSubjectPermissionErrorSupersededRoot},
		{"ts.orch.>", NatsSubjectPermissionErrorOutsideControlRoot},
		{"$SYS.>", NatsSubjectPermissionErrorPlatformReserved},
		{"ts.product.v1.>", NatsSubjectPermissionErrorOutsideControlRoot},
	}

	for _, testCase := range rejected {
		ok, err := NatsSubjectTaxonomy.TryValidatePermissionPattern(testCase.pattern)
		if ok || err != testCase.want {
			t.Fatalf("pattern %q: ok = %v, error = %v", testCase.pattern, ok, err)
		}
	}

	agentToken := must(t, func() (string, error) { return NatsSubjectTaxonomy.HostAgentSubjectToken(testAgentIdentity) })
	for _, pattern := range []string{
		"ts.orch.v2.gru.desired.>",
		"ts.orch.v2.gru.command.>",
		"ts.orch.v2.gru.observation.>",
		"ts.orch.v2.gru.operation.>",
		"ts.orch.v2.gru.query.>",
		"ts.orch.v2.gru.audit.>",
		"ts.orch.v2.gru.agent." + agentToken + ".command.>",
		"ts.orch.v2.global.desired.>",
		"ts.orch.v2.global.release.ci.job.>",
		"ts.orch.v2.global.query.cells",
	} {
		if ok, err := NatsSubjectTaxonomy.TryValidatePermissionPattern(pattern); !ok || err != NatsSubjectPermissionErrorNone {
			t.Fatalf("closed permission %q rejected: %v", pattern, err)
		}
	}

	// A pinned regional permission never matches another Region's subjects.
	pinned := testPattern(
		must(t, func() (string, error) {
			return NatsSubjectTaxonomy.RegionalFamilyPattern("gru", NatsSubjectTaxonomy.DesiredFamilySegment())
		}),
		NatsSubjectTaxonomy.GrammarLimits())
	if pinned.Matches(testConcreteSubject("ts.orch.v2.sfo.desired.gitops", NatsSubjectTaxonomy.GrammarLimits())) {
		t.Fatal("pinned GRU permission must not match SFO subjects")
	}

	if !pinned.Matches(testConcreteSubject(
		must(t, func() (string, error) { return NatsSubjectTaxonomy.CellSpecSubject("gru") }), NatsSubjectTaxonomy.GrammarLimits())) {
		t.Fatal("pinned GRU permission must match GRU CellSpec subjects")
	}
}

func TestCustomerProvidedTextNeverBecomesASubjectToken(t *testing.T) {
	admitted := []string{
		must(t, func() (string, error) { return NatsSubjectTaxonomy.CellSpecSubject("gru") }),
		NatsSubjectTaxonomy.GlobalDirectoryQuerySubject(),
		must(t, func() (string, error) {
			return NatsSubjectTaxonomy.HostAgentCommandSubject("gru", testAgentIdentity, "start")
		}),
		must(t, func() (string, error) { return NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1") }),
	}

	for _, subject := range admitted {
		if ok, err := NatsSubjectTaxonomy.TryAdmitSubject(subject); !ok || err != NatsSubjectAdmissionErrorNone {
			t.Fatalf("closed subject %q must be admissible: %v", subject, err)
		}
	}

	rejected := []struct {
		subject string
		want    NatsSubjectAdmissionError
	}{
		{"ts.orch.v2.gru.desired.café", NatsSubjectAdmissionErrorCustomerTextInSubject},
		{"ts.orch.v2.gru.query.user@example.com", NatsSubjectAdmissionErrorCustomerTextInSubject},
		{"ts.orch.v2.gru.query.héllo", NatsSubjectAdmissionErrorCustomerTextInSubject},
		{"ts.orch.v2.gru. query.health", NatsSubjectAdmissionErrorMalformedSubject},
		{"ts.orch.v2.gru.agent.enroll", NatsSubjectAdmissionErrorInvalidAgentHashToken},
		{"ts.orch.v1.gru.desired.gitops", NatsSubjectAdmissionErrorSupersededRoot},
		{"ts.product.v1.queue.default", NatsSubjectAdmissionErrorOutsideControlRoot},
		{"$JS.API.STREAM.INFO", NatsSubjectAdmissionErrorPlatformReserved},
		{"ts.orch.v2.gru.unknown.channel", NatsSubjectAdmissionErrorUnknownNamespace},
	}

	for _, testCase := range rejected {
		ok, err := NatsSubjectTaxonomy.TryAdmitSubject(testCase.subject)
		if ok || err != testCase.want {
			t.Fatalf("subject %q: ok = %v, error = %v", testCase.subject, ok, err)
		}
	}
}

func TestNoV1PrefixedSubjectAppearsInAnyV2TaxonomySurface(t *testing.T) {
	// Mirrors the reflection walk over the taxonomy's public const fields with
	// an explicit inventory of those constants.
	constants := map[string]string{
		"Root":                              NatsSubjectTaxonomy.Root(),
		"SupersededRoot":                    NatsSubjectTaxonomy.SupersededRoot(),
		"GlobalScopeToken":                  NatsSubjectTaxonomy.GlobalScopeToken(),
		"RegionPlaceholderToken":            NatsSubjectTaxonomy.RegionPlaceholderToken(),
		"AgentHashPlaceholderToken":         NatsSubjectTaxonomy.AgentHashPlaceholderToken(),
		"GlobalRoot":                        NatsSubjectTaxonomy.GlobalRoot(),
		"GlobalDirectoryQuerySubject":       NatsSubjectTaxonomy.GlobalDirectoryQuerySubject(),
		"GlobalCellSpecPrefix":              NatsSubjectTaxonomy.GlobalCellSpecPrefix(),
		"GlobalAcceptedReleasePrefix":       NatsSubjectTaxonomy.GlobalAcceptedReleasePrefix(),
		"CiForgejoTriggerSubject":           NatsSubjectTaxonomy.CiForgejoTriggerSubject(),
		"CiRuntimeProofSubject":             NatsSubjectTaxonomy.CiRuntimeProofSubject(),
		"CiJobSubjectPrefix":                NatsSubjectTaxonomy.CiJobSubjectPrefix(),
		"DesiredFamilySegment":              NatsSubjectTaxonomy.DesiredFamilySegment(),
		"ReleaseFamilySegment":              NatsSubjectTaxonomy.ReleaseFamilySegment(),
		"QueryFamilySegment":                NatsSubjectTaxonomy.QueryFamilySegment(),
		"CommandFamilySegment":              NatsSubjectTaxonomy.CommandFamilySegment(),
		"ObservationFamilySegment":          NatsSubjectTaxonomy.ObservationFamilySegment(),
		"OperationFamilySegment":            NatsSubjectTaxonomy.OperationFamilySegment(),
		"RegionalAuditPrefixSegment":        NatsSubjectTaxonomy.RegionalAuditPrefixSegment(),
		"RegionalAgentPrefixSegment":        NatsSubjectTaxonomy.RegionalAgentPrefixSegment(),
		"RegionalDesiredFamilyTemplate":     NatsSubjectTaxonomy.RegionalDesiredFamilyTemplate(),
		"RegionalOperationFamilyTemplate":   NatsSubjectTaxonomy.RegionalOperationFamilyTemplate(),
		"RegionalObservationFamilyTemplate": NatsSubjectTaxonomy.RegionalObservationFamilyTemplate(),
		"RegionalCellSpecTemplate":          NatsSubjectTaxonomy.RegionalCellSpecTemplate(),
		"RegionalRuntimeStartupTemplate":    NatsSubjectTaxonomy.RegionalRuntimeStartupTemplate(),
		"GlobalCiFamilyPattern":             NatsSubjectTaxonomy.GlobalCiFamilyPattern(),
	}

	if len(constants) < 8 {
		t.Fatal("the taxonomy constant inventory is incomplete")
	}

	if constants["Root"] != "ts.orch.v2" {
		t.Fatal("root constant mismatch")
	}

	for name, value := range constants {
		if name == "SupersededRoot" || name == "RegionPlaceholderToken" || name == "AgentHashPlaceholderToken" {
			continue
		}

		if strings.HasPrefix(value, NatsSubjectTaxonomy.SupersededRoot()+".") {
			t.Fatalf("constant %s=%q must not live under the superseded v1 root", name, value)
		}
	}

	composed := []string{
		NatsSubjectTaxonomy.GlobalDirectoryQuerySubject(),
		must(t, func() (string, error) { return NatsSubjectTaxonomy.GlobalCellSpecSubject("sfo") }),
		NatsSubjectTaxonomy.CiForgejoTriggerSubject(),
		NatsSubjectTaxonomy.CiRuntimeProofSubject(),
		NatsSubjectTaxonomy.CiJobSubjectPrefix(),
		must(t, func() (string, error) { return NatsSubjectTaxonomy.CellSpecSubject("gru") }),
		must(t, func() (string, error) { return NatsSubjectTaxonomy.DirectDeliverySubject("gru") }),
		must(t, func() (string, error) { return NatsSubjectTaxonomy.OperationJournalCreateSubject("gru") }),
		must(t, func() (string, error) { return NatsSubjectTaxonomy.RuntimeStartupSubject("gru", "controller-1") }),
		must(t, func() (string, error) { return NatsSubjectTaxonomy.HostAgentSubjectRoot("gru", testAgentIdentity) }),
		must(t, func() (string, error) {
			return NatsSubjectTaxonomy.RegionalFamilyPattern("fra", NatsSubjectTaxonomy.RegionalAuditPrefixSegment())
		}),
		NatsSubjectTaxonomy.GlobalFamilyPattern(NatsSubjectTaxonomy.ReleaseFamilySegment()),
	}

	for _, subject := range composed {
		if !strings.HasPrefix(subject, NatsSubjectTaxonomy.Root()+".") {
			t.Fatalf("composed subject %q must live under the v2 root", subject)
		}

		if NatsSubjectTaxonomy.Classify(subject) == NatsSubjectNamespaceUnknown {
			t.Fatalf("composed subject %q must classify", subject)
		}
	}

	for _, prefix := range []string{NatsSubjectTaxonomy.GlobalRoot(), must(t, func() (string, error) { return NatsSubjectTaxonomy.RegionalRoot("gru") })} {
		if !strings.HasPrefix(prefix, NatsSubjectTaxonomy.Root()+".") {
			t.Fatalf("prefix %q must live under the v2 root", prefix)
		}

		if strings.HasPrefix(prefix, NatsSubjectTaxonomy.SupersededRoot()+".") {
			t.Fatalf("prefix %q must not live under the v1 root", prefix)
		}
	}

	for _, family := range NatsSubjectTaxonomy.Families() {
		if strings.HasPrefix(family.Pattern, NatsSubjectTaxonomy.SupersededRoot()+".") {
			t.Fatalf("family %q must not live under the v1 root", family.Pattern)
		}
	}

	for _, grants := range ProtocolManifestLoaded().AccountKinds {
		patterns := append(append([]string{}, grants.Publish...), grants.Subscribe...)
		for _, pattern := range patterns {
			if strings.HasPrefix(pattern, NatsSubjectTaxonomy.SupersededRoot()+".") {
				t.Fatalf("account kind %q must not hold v1 permissions", grants.Kind)
			}
		}
	}
}
