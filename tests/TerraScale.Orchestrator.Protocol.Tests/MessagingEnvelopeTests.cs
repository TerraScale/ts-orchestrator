using TerraScale.Orchestrator.Contracts;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Protocol.Tests;

public sealed class MessagingEnvelopeTests
{
    private const string PayloadType = "cellspec-v1";

    private static readonly DateTimeOffset Now = ProtocolTestData.Now;

    private static MessageIdentityToken Token(string value)
    {
        MessageIdentityToken.TryCreate(value, out var token);
        return token;
    }

    private static MessagingEnvelope Envelope(
        CommandEnvelope? command = null,
        MessagingSchemaVersion? schema = null,
        MessageIdentityToken? messageId = null,
        MessagingSource? source = null,
        MessagingTargetScope? target = null,
        string? payloadType = null,
        MessagingTraceContext? trace = null,
        DateTimeOffset? observedAt = null) => new(
        schema ?? MessagingSchemaVersion.Current,
        messageId ?? Token("message-1"),
        Token("correlation-1"),
        null,
        source ?? new MessagingSource("controller-1", "session-1", "gru", "orchestrator-control-gru"),
        target ?? new MessagingTargetScope(
            NatsSubjectNamespace.RegionalControl,
            NatsSubjectTaxonomy.CellSpecSubject("gru"),
            "gru"),
        payloadType ?? PayloadType,
        command ?? ProtocolTestData.ValidEnvelope(),
        trace ?? new MessagingTraceContext(new string('a', 32), new string('b', 16)),
        observedAt ?? Now);

    private static MessagingValidationContext Context(
        CommandValidationContext? commandContext = null,
        IReadOnlySet<int>? majors = null,
        IReadOnlySet<string>? payloadTypes = null) => new(
        majors ?? new HashSet<int> { 1 },
        payloadTypes ?? new HashSet<string>(StringComparer.Ordinal) { PayloadType },
        commandContext ?? ProtocolTestData.ValidContext());

    [Test]
    public async Task A_well_formed_envelope_over_a_valid_signed_command_is_accepted()
    {
        var envelope = Envelope();
        var result = MessagingEnvelopeValidator.Validate(envelope, Context());

        await Assert.That(result.IsAccepted).IsTrue();
        await Assert.That(result.Error).IsEqualTo(MessagingEnvelopeError.None);
        await Assert.That(result.Envelope).IsNotNull();
    }

    [Test]
    public async Task An_unknown_major_schema_version_fails_closed()
    {
        foreach (var offered in new[] { 0, 2, 99 })
        {
            var result = MessagingEnvelopeValidator.Validate(
                Envelope(schema: new MessagingSchemaVersion(offered, 0)), Context());
            await Assert.That(result.Error).IsEqualTo(MessagingEnvelopeError.UnknownMajorVersion);
            await Assert.That(result.IsAccepted).IsFalse();
        }
    }

    [Test]
    public async Task Malformed_identity_or_source_fails_closed()
    {
        var nullEnvelope = MessagingEnvelopeValidator.Validate(null, Context());
        await Assert.That(nullEnvelope.Error).IsEqualTo(MessagingEnvelopeError.NullEnvelope);

        var emptyMessageId = MessagingEnvelopeValidator.Validate(
            Envelope(messageId: Token("")), Context());
        await Assert.That(emptyMessageId.Error).IsEqualTo(MessagingEnvelopeError.MalformedEnvelope);

        var controlCharacterMessageId = MessagingEnvelopeValidator.Validate(
            Envelope(messageId: Token("message1")), Context());
        await Assert.That(controlCharacterMessageId.Error).IsEqualTo(MessagingEnvelopeError.MalformedEnvelope);

        var invalidSource = MessagingEnvelopeValidator.Validate(
            Envelope(source: new MessagingSource("", "session-1", "gru", "cluster")), Context());
        await Assert.That(invalidSource.Error).IsEqualTo(MessagingEnvelopeError.MalformedEnvelope);
    }

    [Test]
    public async Task A_malformed_subject_fails_closed()
    {
        var whitespace = MessagingEnvelopeValidator.Validate(
            Envelope(target: new MessagingTargetScope(
                NatsSubjectNamespace.RegionalControl, "ts.orch.v1.gru. query.health", null)), Context());
        await Assert.That(whitespace.Error).IsEqualTo(MessagingEnvelopeError.MalformedSubject);

        var wildcard = MessagingEnvelopeValidator.Validate(
            Envelope(target: new MessagingTargetScope(
                NatsSubjectNamespace.RegionalControl, "ts.orch.v1.gru.query.>", null)), Context());
        await Assert.That(wildcard.Error).IsEqualTo(MessagingEnvelopeError.MalformedSubject);

        var empty = MessagingEnvelopeValidator.Validate(
            Envelope(target: new MessagingTargetScope(NatsSubjectNamespace.RegionalControl, "", null)), Context());
        await Assert.That(empty.Error).IsEqualTo(MessagingEnvelopeError.MalformedEnvelope);
    }

    [Test]
    public async Task A_subject_outside_the_closed_taxonomy_fails_closed()
    {
        var productPlane = MessagingEnvelopeValidator.Validate(
            Envelope(target: new MessagingTargetScope(
                NatsSubjectNamespace.ProductPlane, "ts.product.v1.queue.default", null)), Context());
        await Assert.That(productPlane.Error).IsEqualTo(MessagingEnvelopeError.SubjectOutsideClosedTaxonomy);

        var unknown = MessagingEnvelopeValidator.Validate(
            Envelope(target: new MessagingTargetScope(
                NatsSubjectNamespace.RegionalControl, "ts.orch.v1.gru.unknown.channel", null)), Context());
        await Assert.That(unknown.Error).IsEqualTo(MessagingEnvelopeError.SubjectOutsideClosedTaxonomy);
    }

    [Test]
    public async Task A_declared_namespace_that_disagrees_with_the_subject_fails_closed()
    {
        var declaredRegional = MessagingEnvelopeValidator.Validate(
            Envelope(target: new MessagingTargetScope(
                NatsSubjectNamespace.RegionalControl,
                NatsSubjectTaxonomy.GlobalDirectoryQuerySubject,
                null)), Context());
        await Assert.That(declaredRegional.Error).IsEqualTo(MessagingEnvelopeError.DeclaredNamespaceMismatch);

        var declaredGlobal = MessagingEnvelopeValidator.Validate(
            Envelope(target: new MessagingTargetScope(
                NatsSubjectNamespace.GlobalDirectory,
                NatsSubjectTaxonomy.CellSpecSubject("gru"),
                "gru")), Context());
        await Assert.That(declaredGlobal.Error).IsEqualTo(MessagingEnvelopeError.DeclaredNamespaceMismatch);

        var unspecified = MessagingEnvelopeValidator.Validate(
            Envelope(target: new MessagingTargetScope(
                NatsSubjectNamespace.Unspecified,
                NatsSubjectTaxonomy.CellSpecSubject("gru"),
                "gru")), Context());
        await Assert.That(unspecified.Error).IsEqualTo(MessagingEnvelopeError.DeclaredNamespaceMismatch);
    }

    [Test]
    public async Task A_global_per_cell_subject_is_validated_against_its_cell_scope()
    {
        // Defense in depth: ts.orch.v1.global.desired.gitops.<cell> carries a cell scope even
        // though it lives under the global root, so a subject naming another cell fails closed.
        var mismatch = MessagingEnvelopeValidator.Validate(
            Envelope(target: new MessagingTargetScope(
                NatsSubjectNamespace.GlobalAuthority,
                NatsSubjectTaxonomy.GlobalCellSpecSubject("sfo"),
                null)), Context());
        await Assert.That(mismatch.Error).IsEqualTo(MessagingEnvelopeError.SubjectCellMismatch);

        var matching = MessagingEnvelopeValidator.Validate(
            Envelope(target: new MessagingTargetScope(
                NatsSubjectNamespace.GlobalAuthority,
                NatsSubjectTaxonomy.GlobalCellSpecSubject("gru"),
                null)), Context());
        await Assert.That(matching.IsAccepted).IsTrue();
    }

    [Test]
    public async Task Cell_scope_extraction_covers_regional_and_global_per_cell_shapes_only()
    {
        await Assert.That(MessagingEnvelopeValidator.ExtractCellScope(NatsSubjectTaxonomy.CellSpecSubject("gru")))
            .IsEqualTo("gru");
        await Assert.That(MessagingEnvelopeValidator.ExtractCellScope(NatsSubjectTaxonomy.GlobalCellSpecSubject("sfo")))
            .IsEqualTo("sfo");

        // Global subjects without a per-cell shape carry no cell scope.
        await Assert.That(MessagingEnvelopeValidator.ExtractCellScope(NatsSubjectTaxonomy.GlobalDirectoryQuerySubject))
            .IsNull();
        await Assert.That(MessagingEnvelopeValidator.ExtractCellScope(NatsSubjectTaxonomy.CiForgejoTriggerSubject))
            .IsNull();
        await Assert.That(MessagingEnvelopeValidator.ExtractCellScope(NatsSubjectTaxonomy.CiRuntimeProofSubject))
            .IsNull();
        await Assert.That(MessagingEnvelopeValidator.ExtractCellScope(NatsSubjectTaxonomy.GlobalRoot + ".journal.ledger"))
            .IsNull();

        // Only the canonical global per-cell shape is scoped; a longer subject under the same
        // prefix is not canonical and extracts nothing rather than guessing.
        await Assert.That(MessagingEnvelopeValidator.ExtractCellScope(
                NatsSubjectTaxonomy.GlobalCellSpecSubject("gru") + ".extra"))
            .IsNull();
    }

    [Test]
    public async Task Subject_source_and_command_must_agree_on_the_cell()
    {
        var subjectNamesAnotherCell = MessagingEnvelopeValidator.Validate(
            Envelope(target: new MessagingTargetScope(
                NatsSubjectNamespace.RegionalControl,
                NatsSubjectTaxonomy.CellSpecSubject("sfo"),
                "gru")), Context());
        await Assert.That(subjectNamesAnotherCell.Error).IsEqualTo(MessagingEnvelopeError.SubjectCellMismatch);

        var sourceNamesAnotherCell = MessagingEnvelopeValidator.Validate(
            Envelope(source: new MessagingSource("controller-1", "session-1", "sfo", "orchestrator-control-sfo")),
            Context());
        await Assert.That(sourceNamesAnotherCell.Error).IsEqualTo(MessagingEnvelopeError.SourceCellMismatch);

        var targetNamesAnotherCell = MessagingEnvelopeValidator.Validate(
            Envelope(target: new MessagingTargetScope(
                NatsSubjectNamespace.RegionalControl,
                NatsSubjectTaxonomy.CellSpecSubject("gru"),
                "sfo")), Context());
        await Assert.That(targetNamesAnotherCell.Error).IsEqualTo(MessagingEnvelopeError.SubjectCellMismatch);
    }

    [Test]
    public async Task An_unpermitted_payload_type_fails_closed()
    {
        var result = MessagingEnvelopeValidator.Validate(
            Envelope(payloadType: "unknown-payload-type-v9"), Context());
        await Assert.That(result.Error).IsEqualTo(MessagingEnvelopeError.PayloadTypeNotPermitted);
    }

    [Test]
    public async Task A_malformed_trace_context_fails_closed()
    {
        var result = MessagingEnvelopeValidator.Validate(
            Envelope(trace: new MessagingTraceContext("not-hex", new string('b', 16))), Context());
        await Assert.That(result.Error).IsEqualTo(MessagingEnvelopeError.InvalidTraceContext);
    }

    [Test]
    public async Task Signed_command_rejections_surface_as_typed_messaging_rejections()
    {
        var expired = MessagingEnvelopeValidator.Validate(
            Envelope(command: ProtocolTestData.ValidEnvelope(
                issuedAt: Now.AddHours(-2), expiresAt: Now.AddHours(-1))),
            Context());
        await Assert.That(expired.Error).IsEqualTo(MessagingEnvelopeError.CommandRejected);
        await Assert.That(expired.CommandError).IsEqualTo(CommandValidationError.Expired);

        var delayed = MessagingEnvelopeValidator.Validate(
            Envelope(command: ProtocolTestData.ValidEnvelope(
                issuedAt: Now.AddMinutes(30), expiresAt: Now.AddMinutes(60))),
            Context(commandContext: ProtocolTestData.ValidContext()));
        await Assert.That(delayed.CommandError).IsEqualTo(CommandValidationError.NotYetValid);

        var wrongCell = MessagingEnvelopeValidator.Validate(
            Envelope(
                command: ProtocolTestData.ValidEnvelope(cell: ProtocolTestData.Cell("sfo")),
                source: new MessagingSource("controller-1", "session-1", "sfo", "orchestrator-control-sfo"),
                target: new MessagingTargetScope(
                    NatsSubjectNamespace.GlobalDirectory,
                    NatsSubjectTaxonomy.GlobalDirectoryQuerySubject,
                    null)),
            Context());
        await Assert.That(wrongCell.CommandError).IsEqualTo(CommandValidationError.WrongCell);

        var staleEpoch = MessagingEnvelopeValidator.Validate(
            Envelope(command: ProtocolTestData.ValidEnvelope(epoch: ProtocolTestData.Epoch(6))),
            Context());
        await Assert.That(staleEpoch.CommandError).IsEqualTo(CommandValidationError.StaleWriterEpoch);

        // Invalid signature SHAPE: the signed-command contract's well-formedness gate rejects it
        // before any verifier runs.
        var shapelessSignatureCommand = new CommandEnvelope(
            ProtocolTestData.Protocol(1),
            ProtocolTestData.Cell("gru"),
            ProtocolTestData.Aggregate("allocation/42"),
            ProtocolTestData.Generation(10),
            ProtocolTestData.Epoch(7),
            ProtocolTestData.Operation("operation/abc"),
            ProtocolTestData.Idempotency("idempotency/abc"),
            Now.AddMinutes(-1),
            Now.AddMinutes(1),
            ProtocolTestData.Attempt(1),
            OpaquePayload.CopyFrom(ProtocolTestData.PayloadBytes),
            ProtocolTestData.Digest(ProtocolTestData.PayloadBytes),
            null!);
        var invalidSignatureShape = MessagingEnvelopeValidator.Validate(
            Envelope(command: shapelessSignatureCommand), Context());
        await Assert.That(invalidSignatureShape.Error).IsEqualTo(MessagingEnvelopeError.CommandRejected);
        await Assert.That(invalidSignatureShape.CommandError).IsEqualTo(CommandValidationError.MalformedEnvelope);

        var digestDisagreement = MessagingEnvelopeValidator.Validate(
            Envelope(command: ProtocolTestData.ValidEnvelope(digest: ProtocolTestData.Digest([9, 9, 9, 9]))),
            Context());
        await Assert.That(digestDisagreement.CommandError).IsEqualTo(CommandValidationError.PayloadDigestMismatch);

        var invalidSignature = MessagingEnvelopeValidator.Validate(
            Envelope(command: ProtocolTestData.ValidEnvelope()),
            Context(commandContext: ProtocolTestData.ValidContext(
                signatureVerifier: new TestSignatureVerifier(isValid: false))));
        await Assert.That(invalidSignature.CommandError).IsEqualTo(CommandValidationError.InvalidSignature);
    }

    [Test]
    public async Task A_missing_or_unwell_context_fails_closed()
    {
        var result = MessagingEnvelopeValidator.Validate(Envelope(), null);
        await Assert.That(result.Error).IsEqualTo(MessagingEnvelopeError.MalformedEnvelope);

        var emptyMajors = MessagingEnvelopeValidator.Validate(
            Envelope(),
            new MessagingValidationContext(
                new HashSet<int>(),
                new HashSet<string>(StringComparer.Ordinal) { PayloadType },
                ProtocolTestData.ValidContext()));
        await Assert.That(emptyMajors.Error).IsEqualTo(MessagingEnvelopeError.MalformedEnvelope);
    }

    [Test]
    public async Task The_message_envelope_extends_rather_than_duplicates_the_signed_command_contract()
    {
        var envelope = Envelope();

        await Assert.That(envelope.Command).IsNotNull();
        await Assert.That(envelope.Command.IdempotencyKey.Value).IsEqualTo("idempotency/abc");
        await Assert.That(envelope.Command.OperationId.Value).IsEqualTo("operation/abc");
        await Assert.That(envelope.Command.WriterEpoch.Value).IsEqualTo(7);
        await Assert.That(envelope.Command.DesiredGeneration.Value).IsEqualTo(10);
        await Assert.That(envelope.SchemaVersion).IsEqualTo(MessagingSchemaVersion.Current);
        await Assert.That(envelope.PayloadType).IsEqualTo(PayloadType);
    }
}
