package protocol

import "terrascale.tech/orchestrator/src/orchestrator/contracts"
import "terrascale.tech/orchestrator/src/orchestrator/natspolicy"

import (
	"strings"
	"testing"
	"time"
)

const payloadType = "cellspec-v1"

func testToken(value string) MessageIdentityToken {
	token, _ := MessageIdentityTokenTryCreate(value)
	return token
}

func messagingEnvelope(t *testing.T, overrides ...func(*messagingEnvelopeOptions)) *MessagingEnvelope {
	defaultSubject, subjectErr := natspolicy.NatsSubjectTaxonomy.CellSpecSubject("gru")
	if subjectErr != nil {
		t.Fatalf("default subject composition failed: %v", subjectErr)
	}

	options := messagingEnvelopeOptions{
		schema:      MessagingSchemaVersionCurrent,
		messageId:   testToken("message-1"),
		source:      MessagingSource{Instance: "controller-1", Session: "session-1", Cell: "gru", Cluster: "orchestrator-control-gru"},
		target:      messagingTarget(natspolicy.NatsSubjectNamespaceRegionalControl, defaultSubject, "gru"),
		payloadType: payloadType,
		command:     ptrOf(validEnvelope()),
		trace:       &MessagingTraceContext{TraceId: strings.Repeat("a", 32), SpanId: strings.Repeat("b", 16)},
		observedAt:  protocolNow,
	}

	for _, override := range overrides {
		override(&options)
	}

	return &MessagingEnvelope{
		SchemaVersion: options.schema,
		MessageId:     options.messageId,
		CorrelationId: ptrOf(testToken("correlation-1")),
		CausationId:   nil,
		Source:        options.source,
		Target:        options.target,
		PayloadType:   options.payloadType,
		Command:       options.command,
		TraceContext:  options.trace,
		ObservedAt:    options.observedAt,
	}
}

type messagingEnvelopeOptions struct {
	schema      MessagingSchemaVersion
	messageId   MessageIdentityToken
	source      MessagingSource
	target      MessagingTargetScope
	payloadType string
	command     *CommandEnvelope
	trace       *MessagingTraceContext
	observedAt  time.Time
}

func messagingTarget(namespace natspolicy.NatsSubjectNamespace, subject string, cell string) MessagingTargetScope {
	scope := MessagingTargetScope{Namespace: namespace, Subject: subject}
	if cell != "" {
		scope.Cell = &cell
	}

	return scope
}

func mustT(t *testing.T, compose func() (string, error)) string {
	t.Helper()
	value, err := compose()
	if err != nil {
		t.Fatalf("subject composition failed: %v", err)
	}

	return value
}

func messagingContext(overrides ...func(*messagingContextOptions)) *MessagingValidationContext {
	options := messagingContextOptions{
		majors:       map[int]struct{}{MessagingSchemaVersionCurrent.Major: {}},
		payloadTypes: map[string]struct{}{payloadType: {}},
		command:      validContext(),
	}

	for _, override := range overrides {
		override(&options)
	}

	return NewMessagingValidationContext(options.majors, options.payloadTypes, options.command)
}

type messagingContextOptions struct {
	majors       map[int]struct{}
	payloadTypes map[string]struct{}
	command      *CommandValidationContext
}

func TestAWellFormedEnvelopeOverAValidSignedCommandIsAccepted(t *testing.T) {
	result := MessagingEnvelopeValidator.Validate(messagingEnvelope(t), messagingContext())

	if !result.IsAccepted() || result.Error != MessagingEnvelopeErrorNone || result.Envelope == nil {
		t.Fatalf("result = %v", result.Error)
	}
}

func TestAnUnknownMajorSchemaVersionFailsClosed(t *testing.T) {
	for _, offered := range []int{0, 2, 3, 99} {
		result := MessagingEnvelopeValidator.Validate(
			messagingEnvelope(t, func(o *messagingEnvelopeOptions) { o.schema = MessagingSchemaVersion{Major: offered} }),
			messagingContext())
		if result.Error != MessagingEnvelopeErrorUnknownMajorVersion || result.IsAccepted() {
			t.Fatalf("major %d: error = %v", offered, result.Error)
		}
	}
}

func TestMalformedIdentityOrSourceFailsClosed(t *testing.T) {
	nullEnvelope := MessagingEnvelopeValidator.Validate(nil, messagingContext())
	if nullEnvelope.Error != MessagingEnvelopeErrorNullEnvelope {
		t.Fatalf("null envelope error = %v", nullEnvelope.Error)
	}

	emptyMessageId := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) { o.messageId = testToken("") }),
		messagingContext())
	if emptyMessageId.Error != MessagingEnvelopeErrorMalformedEnvelope {
		t.Fatalf("empty message id error = %v", emptyMessageId.Error)
	}

	controlCharacterMessageId := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) { o.messageId = testToken("message\x01") }),
		messagingContext())
	if controlCharacterMessageId.Error != MessagingEnvelopeErrorMalformedEnvelope {
		t.Fatalf("control character message id error = %v", controlCharacterMessageId.Error)
	}

	invalidSource := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.source = MessagingSource{Instance: "", Session: "session-1", Cell: "gru", Cluster: "cluster"}
		}),
		messagingContext())
	if invalidSource.Error != MessagingEnvelopeErrorMalformedEnvelope {
		t.Fatalf("invalid source error = %v", invalidSource.Error)
	}
}

func TestMessageIdentityBoundUsesV1UTF16CodeUnits(t *testing.T) {
	atLimit := strings.Repeat("\U0001F680", 64)
	token, ok := MessageIdentityTokenTryCreate(atLimit)
	if !ok || !token.IsValid() {
		t.Fatal("message identity at 128 v1 code units was rejected")
	}

	if token, ok := MessageIdentityTokenTryCreate(atLimit + "a"); ok || token.IsValid() {
		t.Fatal("message identity over 128 v1 code units was accepted")
	}
}

func TestAMalformedSubjectFailsClosed(t *testing.T) {
	whitespace := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.target = messagingTarget(natspolicy.NatsSubjectNamespaceRegionalControl, "ts.orch.v1.gru. query.health", "")
		}),
		messagingContext())
	if whitespace.Error != MessagingEnvelopeErrorMalformedSubject {
		t.Fatalf("whitespace subject error = %v", whitespace.Error)
	}

	wildcard := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.target = messagingTarget(natspolicy.NatsSubjectNamespaceRegionalControl, "ts.orch.v1.gru.query.>", "")
		}),
		messagingContext())
	if wildcard.Error != MessagingEnvelopeErrorMalformedSubject {
		t.Fatalf("wildcard subject error = %v", wildcard.Error)
	}

	empty := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.target = messagingTarget(natspolicy.NatsSubjectNamespaceRegionalControl, "", "")
		}),
		messagingContext())
	if empty.Error != MessagingEnvelopeErrorMalformedEnvelope {
		t.Fatalf("empty subject error = %v", empty.Error)
	}
}

func TestASubjectOutsideTheClosedTaxonomyFailsClosed(t *testing.T) {
	productPlane := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.target = messagingTarget(natspolicy.NatsSubjectNamespaceProductPlane, "ts.product.v1.queue.default", "")
		}),
		messagingContext())
	if productPlane.Error != MessagingEnvelopeErrorSubjectOutsideClosedTaxonomy {
		t.Fatalf("product plane error = %v", productPlane.Error)
	}

	unknown := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.target = messagingTarget(natspolicy.NatsSubjectNamespaceRegionalControl, "ts.orch.v1.gru.unknown.channel", "")
		}),
		messagingContext())
	if unknown.Error != MessagingEnvelopeErrorSubjectOutsideClosedTaxonomy {
		t.Fatalf("unknown family error = %v", unknown.Error)
	}

}

func TestADeclaredNamespaceThatDisagreesWithTheSubjectFailsClosed(t *testing.T) {
	declaredRegional := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.target = messagingTarget(natspolicy.NatsSubjectNamespaceRegionalControl, natspolicy.NatsSubjectTaxonomy.GlobalDirectoryQuerySubject(), "")
		}),
		messagingContext())
	if declaredRegional.Error != MessagingEnvelopeErrorDeclaredNamespaceMismatch {
		t.Fatalf("declared regional error = %v", declaredRegional.Error)
	}

	cellSpecGru := mustT(t, func() (string, error) { return natspolicy.NatsSubjectTaxonomy.CellSpecSubject("gru") })
	declaredGlobal := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.target = messagingTarget(natspolicy.NatsSubjectNamespaceGlobalDirectory, cellSpecGru, "gru")
		}),
		messagingContext())
	if declaredGlobal.Error != MessagingEnvelopeErrorDeclaredNamespaceMismatch {
		t.Fatalf("declared global error = %v", declaredGlobal.Error)
	}

	unspecified := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.target = messagingTarget(natspolicy.NatsSubjectNamespaceUnspecified, cellSpecGru, "gru")
		}),
		messagingContext())
	if unspecified.Error != MessagingEnvelopeErrorDeclaredNamespaceMismatch {
		t.Fatalf("unspecified namespace error = %v", unspecified.Error)
	}
}

func TestAGlobalPerCellSubjectIsValidatedAgainstItsCellScope(t *testing.T) {
	// Defense in depth: ts.orch.v1.global.desired.gitops.<cell> carries a cell
	// scope even though it lives under the global root, so a target naming
	// another cell fails closed.
	mismatch := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.target = messagingTarget(natspolicy.NatsSubjectNamespaceGlobalAuthority,
				mustT(t, func() (string, error) { return natspolicy.NatsSubjectTaxonomy.GlobalCellSpecSubject("sfo") }), "sfo")
		}),
		messagingContext())
	if mismatch.Error != MessagingEnvelopeErrorSubjectCellMismatch {
		t.Fatalf("mismatched global per-cell error = %v", mismatch.Error)
	}

	matching := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.target = messagingTarget(natspolicy.NatsSubjectNamespaceGlobalAuthority,
				mustT(t, func() (string, error) { return natspolicy.NatsSubjectTaxonomy.GlobalCellSpecSubject("gru") }), "gru")
		}),
		messagingContext())
	if !matching.IsAccepted() {
		t.Fatalf("matching global per-cell error = %v", matching.Error)
	}
}

func TestAGlobalPerCellSubjectCannotBypassCellValidationWhenTargetCellIsOmitted(t *testing.T) {
	result := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.target = messagingTarget(natspolicy.NatsSubjectNamespaceGlobalAuthority,
				mustT(t, func() (string, error) { return natspolicy.NatsSubjectTaxonomy.GlobalCellSpecSubject("sfo") }), "")
		}),
		messagingContext())

	if result.Error != MessagingEnvelopeErrorSubjectCellMismatch || result.IsAccepted() {
		t.Fatalf("error = %v", result.Error)
	}
}

func TestCellScopeExtractionCoversRegionalAndGlobalPerCellShapesOnly(t *testing.T) {
	if cell, ok := extractCellScope(mustT(t, func() (string, error) { return natspolicy.NatsSubjectTaxonomy.CellSpecSubject("gru") })); !ok || cell != "gru" {
		t.Fatalf("regional cell scope = %q", cell)
	}

	if cell, ok := extractCellScope(mustT(t, func() (string, error) { return natspolicy.NatsSubjectTaxonomy.GlobalCellSpecSubject("sfo") })); !ok || cell != "sfo" {
		t.Fatalf("global per-cell scope = %q", cell)
	}

	// Global subjects without a per-cell shape carry no cell scope.
	for _, subject := range []string{
		natspolicy.NatsSubjectTaxonomy.GlobalDirectoryQuerySubject(),
		natspolicy.NatsSubjectTaxonomy.CiForgejoTriggerSubject(),
		natspolicy.NatsSubjectTaxonomy.GlobalAcceptedReleasePrefix() + ".ledger",
		mustT(t, func() (string, error) { return natspolicy.NatsSubjectTaxonomy.GlobalCellSpecSubject("gru") }) + ".extra",
	} {
		if cell, ok := extractCellScope(subject); ok {
			t.Fatalf("subject %q must not carry a cell scope, got %q", subject, cell)
		}
	}
}

func TestSubjectSourceAndCommandMustAgreeOnTheCell(t *testing.T) {
	subjectNamesAnotherCell := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.target = messagingTarget(natspolicy.NatsSubjectNamespaceRegionalControl,
				mustT(t, func() (string, error) { return natspolicy.NatsSubjectTaxonomy.CellSpecSubject("sfo") }), "sfo")
		}),
		messagingContext())
	if subjectNamesAnotherCell.Error != MessagingEnvelopeErrorSubjectCellMismatch {
		t.Fatalf("subject cell mismatch error = %v", subjectNamesAnotherCell.Error)
	}

	sourceNamesAnotherCell := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.source = MessagingSource{Instance: "controller-1", Session: "session-1", Cell: "sfo", Cluster: "orchestrator-control-sfo"}
		}),
		messagingContext())
	if sourceNamesAnotherCell.Error != MessagingEnvelopeErrorSourceCellMismatch {
		t.Fatalf("source cell mismatch error = %v", sourceNamesAnotherCell.Error)
	}

	targetNamesAnotherCell := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.target = messagingTarget(natspolicy.NatsSubjectNamespaceRegionalControl,
				mustT(t, func() (string, error) { return natspolicy.NatsSubjectTaxonomy.CellSpecSubject("gru") }), "sfo")
		}),
		messagingContext())
	if targetNamesAnotherCell.Error != MessagingEnvelopeErrorSubjectCellMismatch {
		t.Fatalf("target cell mismatch error = %v", targetNamesAnotherCell.Error)
	}
}

func TestAnUnpermittedPayloadTypeFailsClosed(t *testing.T) {
	result := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) { o.payloadType = "unknown-payload-type-v9" }),
		messagingContext())
	if result.Error != MessagingEnvelopeErrorPayloadTypeNotPermitted {
		t.Fatalf("error = %v", result.Error)
	}
}

func TestAMalformedTraceContextFailsClosed(t *testing.T) {
	result := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.trace = &MessagingTraceContext{TraceId: "not-hex", SpanId: strings.Repeat("b", 16)}
		}),
		messagingContext())
	if result.Error != MessagingEnvelopeErrorInvalidTraceContext {
		t.Fatalf("error = %v", result.Error)
	}
}

func TestSignedCommandRejectionsSurfaceAsTypedMessagingRejections(t *testing.T) {
	expired := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.command = ptrOf(validEnvelope(
				func(v *validEnvelopeOption) { v.issuedAt = ptrOf(protocolNow.Add(-2 * time.Hour)) },
				func(v *validEnvelopeOption) { v.expiresAt = ptrOf(protocolNow.Add(-time.Hour)) }))
		}),
		messagingContext())
	if expired.Error != MessagingEnvelopeErrorCommandRejected ||
		expired.CommandError != CommandValidationErrorExpired {
		t.Fatalf("expired error = %v/%v", expired.Error, expired.CommandError)
	}

	delayed := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.command = ptrOf(validEnvelope(
				func(v *validEnvelopeOption) { v.issuedAt = ptrOf(protocolNow.Add(30 * time.Minute)) },
				func(v *validEnvelopeOption) { v.expiresAt = ptrOf(protocolNow.Add(60 * time.Minute)) }))
		}),
		messagingContext())
	if delayed.CommandError != CommandValidationErrorNotYetValid {
		t.Fatalf("delayed command error = %v", delayed.CommandError)
	}

	wrongCell := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.command = ptrOf(validEnvelope(func(v *validEnvelopeOption) { v.cell = ptrOf(testCell("sfo")) }))
			o.source = MessagingSource{Instance: "controller-1", Session: "session-1", Cell: "sfo", Cluster: "orchestrator-control-sfo"}
			o.target = messagingTarget(natspolicy.NatsSubjectNamespaceGlobalDirectory, natspolicy.NatsSubjectTaxonomy.GlobalDirectoryQuerySubject(), "")
		}),
		messagingContext())
	if wrongCell.CommandError != CommandValidationErrorWrongCell {
		t.Fatalf("wrong cell command error = %v", wrongCell.CommandError)
	}

	staleEpoch := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.command = ptrOf(validEnvelope(func(v *validEnvelopeOption) { v.epoch = ptrOf(testEpoch(6)) }))
		}),
		messagingContext())
	if staleEpoch.CommandError != CommandValidationErrorStaleWriterEpoch {
		t.Fatalf("stale epoch command error = %v", staleEpoch.CommandError)
	}

	// Invalid signature SHAPE: the signed-command contract's well-formedness
	// gate rejects it before any verifier runs.
	shapelessSignatureCommand := validEnvelope()
	shapelessSignatureCommand.Signature = OpaqueSignature{}
	invalidSignatureShape := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) { o.command = ptrOf(shapelessSignatureCommand) }),
		messagingContext())
	if invalidSignatureShape.Error != MessagingEnvelopeErrorCommandRejected ||
		invalidSignatureShape.CommandError != CommandValidationErrorMalformedEnvelope {
		t.Fatalf("shapeless signature error = %v/%v", invalidSignatureShape.Error, invalidSignatureShape.CommandError)
	}

	digestDisagreement := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t, func(o *messagingEnvelopeOptions) {
			o.command = ptrOf(validEnvelope(func(v *validEnvelopeOption) { v.digest = ptrOf(testDigest([]byte{9, 9, 9, 9})) }))
		}),
		messagingContext())
	if digestDisagreement.CommandError != CommandValidationErrorPayloadDigestMismatch {
		t.Fatalf("digest disagreement error = %v", digestDisagreement.CommandError)
	}

	invalidSignature := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t),
		messagingContext(func(o *messagingContextOptions) {
			o.command = validContext(func(v *validContextOption) { v.signatureVerifier = newTestSignatureVerifier(false, false) })
		}))
	if invalidSignature.CommandError != CommandValidationErrorInvalidSignature {
		t.Fatalf("invalid signature error = %v", invalidSignature.CommandError)
	}
}

func TestAMissingOrUnwellContextFailsClosed(t *testing.T) {
	result := MessagingEnvelopeValidator.Validate(messagingEnvelope(t), nil)
	if result.Error != MessagingEnvelopeErrorMalformedEnvelope {
		t.Fatalf("missing context error = %v", result.Error)
	}

	emptyMajors := MessagingEnvelopeValidator.Validate(
		messagingEnvelope(t),
		NewMessagingValidationContext(
			map[int]struct{}{},
			map[string]struct{}{payloadType: {}},
			validContext()))
	if emptyMajors.Error != MessagingEnvelopeErrorMalformedEnvelope {
		t.Fatalf("empty majors error = %v", emptyMajors.Error)
	}
}

func TestTheMessageEnvelopeExtendsRatherThanDuplicatesTheSignedCommandContract(t *testing.T) {
	envelope := messagingEnvelope(t)

	if envelope.Command == nil {
		t.Fatal("envelope must carry the signed command")
	}

	if envelope.Command.IdempotencyKey.Value != "idempotency/abc" ||
		envelope.Command.OperationId.Value != "operation/abc" ||
		envelope.Command.WriterEpoch.Value != 7 ||
		envelope.Command.DesiredGeneration.Value != 10 {
		t.Fatal("signed command fields differ")
	}

	if envelope.SchemaVersion != MessagingSchemaVersionCurrent || envelope.PayloadType != payloadType {
		t.Fatal("envelope schema or payload type differ")
	}
}

func TestNonCommandEnvelopeStringDoesNotPanic(t *testing.T) {
	envelope := messagingEnvelope(t, func(o *messagingEnvelopeOptions) { o.command = nil })

	if got := envelope.String(); !strings.Contains(got, "Command = <none>") {
		t.Fatalf("string = %q", got)
	}
}

func TestUTF16CodeUnitCount(t *testing.T) {
	tests := []struct {
		value string
		want  int
	}{
		{value: "ascii", want: 5},
		{value: "caf\u00e9", want: 4},
		{value: "\U0001F680", want: 2},
		{value: "a\U0001F680z", want: 4},
	}
	for _, test := range tests {
		if got := contracts.UTF16CodeUnitCount(test.value); got != test.want {
			t.Fatalf("utf16CodeUnitCount(%q) = %d, want %d", test.value, got, test.want)
		}
	}
}
