using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Pure least-privilege and isolation tests for the NATS monitoring identity
/// (issue #23): the plan grants exactly the read-only system subjects, cannot reach
/// control work, JetStream mutation, secret material, or the product plane, and the
/// shared redaction boundary never passes JWTs, seeds, private keys, credentials,
/// or customer payloads.
/// </summary>
public sealed class NatsMonitoringPermissionsTests
{
    [Test]
    public async Task The_plan_grants_exactly_the_read_only_system_subjects_and_an_inbox()
    {
        var plan = NatsMonitoringPermissions.Create();

        await Assert.That(plan.Publish).IsEquivalentTo(NatsMonitoringSubjects.Requests);
        await Assert.That(plan.Subscribe).IsEquivalentTo(
            NatsMonitoringSubjects.AdvisorySubscriptions.Append("_INBOX.>"));

        // Every granted publish is a read-only system service request: no stream,
        // no account data, no wildcard beyond the exact request subjects.
        await Assert.That(plan.Publish.All(static subject =>
            subject.StartsWith("$SYS.REQ.SERVER.PING.", StringComparison.Ordinal))).IsTrue();
        await Assert.That(plan.Publish.All(static subject => !subject.Contains('*', StringComparison.Ordinal)))
            .IsTrue();
        // The only subscriptions are the two advisory wildcards and the inbox.
        await Assert.That(plan.Subscribe.Where(static subject => !subject.StartsWith("_INBOX", StringComparison.Ordinal)))
            .IsEquivalentTo(NatsMonitoringSubjects.AdvisorySubscriptions);
    }

    [Test]
    public async Task The_subject_allowlist_is_minimal_and_exact()
    {
        await Assert.That(NatsMonitoringSubjects.Requests.Count()).IsEqualTo(6);
        await Assert.That(NatsMonitoringSubjects.AdvisorySubscriptions.Count()).IsEqualTo(2);
        await Assert.That(NatsMonitoringSubjects.IsMonitoringSubject("$SYS.REQ.SERVER.PING.GATEWAYZ")).IsTrue();
        await Assert.That(NatsMonitoringSubjects.IsMonitoringSubject("$SYS.REQ.SERVER.PING")).IsFalse();
        await Assert.That(NatsMonitoringSubjects.IsMonitoringSubject("$SYS.REQ.SERVER.PING.SUBSZ")).IsFalse();
        await Assert.That(NatsMonitoringSubjects.IsMonitoringSubject("$SYS.REQ.ACCOUNT.Z")).IsFalse();
        // Only the declared advisory families are admitted, exactly one bounded
        // account token between the root and the advisory segment.
        await Assert.That(NatsMonitoringSubjects.IsAdvisoryDeliverySubject("$SYS.ACCOUNT.REG.ADVISORY.SLOW_CONSUMER")).IsTrue();
        await Assert.That(NatsMonitoringSubjects.IsAdvisoryDeliverySubject("$SYS.JETSTREAM.ADVISORY.MAX_DELIVERIES")).IsTrue();
        await Assert.That(NatsMonitoringSubjects.IsAdvisoryDeliverySubject("$SYS.ACCOUNT.REG.OTHER.ADVISORY.SLOW_CONSUMER")).IsFalse();
        await Assert.That(NatsMonitoringSubjects.IsAdvisoryDeliverySubject("$SYS.ACCOUNT.>")).IsFalse();
        await Assert.That(NatsMonitoringSubjects.IsAdvisoryDeliverySubject("$SYS.ACCOUNT.REG.EVENT")).IsFalse();
    }

    [Test]
    public async Task Monitoring_cannot_reach_control_work_jetstream_mutation_secrets_or_the_product_plane()
    {
        var plan = NatsMonitoringPermissions.Create();
        var granted = (IReadOnlyCollection<string>)plan.Publish
            .Concat(plan.Subscribe)
            .ToArray();

        foreach (var cell in new[] { "gru", "sfo", "fra" })
            foreach (var forbidden in NatsMonitoringPermissions.Forbidden.ControlPublish(cell))
                await Assert.That(NatsMonitoringPermissions.Grants(granted, forbidden))
                    .IsFalse();

        foreach (var forbidden in NatsMonitoringPermissions.Forbidden.GlobalControlPublish()
                     .Concat(NatsMonitoringPermissions.Forbidden.JetStreamMutation())
                     .Concat(NatsMonitoringPermissions.Forbidden.SecretAndJournalReads())
                     .Concat(NatsMonitoringPermissions.Forbidden.ProductPlane()))
            await Assert.That(NatsMonitoringPermissions.Grants(granted, forbidden))
                .IsFalse();

        // The matcher itself proves coverage direction: a granted pattern matches.
        await Assert.That(NatsMonitoringPermissions.Grants(granted, "_INBOX.abc.reply")).IsTrue();
        await Assert.That(NatsMonitoringPermissions.Grants(granted, "$SYS.ACCOUNT.REG.ADVISORY.X")).IsTrue();
    }

    [Test]
    public async Task The_plan_constructor_rejects_every_hostile_grant()
    {
        await Assert.That(() => new NatsMonitoringPermissionPlan(
                ["$JS.API.STREAM.DELETE.>"], ["_INBOX.>"]))
            .Throws<ArgumentException>();
        await Assert.That(() => new NatsMonitoringPermissionPlan(
                ["$SYS.REQ.SERVER.PING.CONNZ", "ts.orch.v1.gru.command.delivery"], ["_INBOX.>"]))
            .Throws<ArgumentException>();
        await Assert.That(() => new NatsMonitoringPermissionPlan(
                ["$SYS.REQ.SERVER.PING.CONNZ", "$SYS.REQ.SERVER.PING.SUBSZ"], ["_INBOX.>"]))
            .Throws<ArgumentException>();
        await Assert.That(() => new NatsMonitoringPermissionPlan(
                ["$SYS.REQ.SERVER.PING.CONNZ"], ["$SYS.>"]))
            .Throws<ArgumentException>();
        await Assert.That(() => new NatsMonitoringPermissionPlan(
                ["$SYS.REQ.SERVER.PING.CONNZ"], ["_INBOX.>", "$KV.ORCH_OPERATIONS.>"]))
            .Throws<ArgumentException>();
        await Assert.That(() => new NatsMonitoringPermissionPlan(
                ["$SYS.REQ.SERVER.PING.CONNZ"], ["_INBOX.>", "product.>"]))
            .Throws<ArgumentException>();
        // A benign inbox-only subscription is grantable, and the canonical plan
        // still constructs: the allowlist itself is the ceiling, not the caller.
        _ = new NatsMonitoringPermissionPlan([], ["_INBOX.>"]);
        _ = NatsMonitoringPermissions.Create();
    }

    [Test]
    public async Task Redaction_never_passes_secrets_or_customer_payloads()
    {
        const string jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N7LHERSL2pFp0.";
        const string seed = "SUANQZRZW5EQRUQU3EFFZSTUYQ25QFJZE4S2GZIIFZTAZLTPUU4ZNSYRU";
        const string pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----";
        var customerPayload = """{"tenant":"acme","order":"secret-customer-material"}""";

        foreach (var dangerous in new[] { jwt, seed, pem, "Bearer abc123def456", "password: hunter2" })
        {
            await Assert.That(NatsMonitoringRedaction.ContainsSecretMaterial(dangerous)).IsTrue();
            var sanitized = NatsMonitoringRedaction.Sanitize($"advisory context {dangerous} trailing");
            await Assert.That(NatsMonitoringRedaction.ContainsSecretMaterial(sanitized)).IsFalse();
            await Assert.That(sanitized).Contains(NatsMonitoringRedaction.RedactedPlaceholder);
        }

        // Customer payloads never enter correlation metadata at all: summaries are
        // bounded text and correlation tokens are opaque lowercase tokens.
        await Assert.That(NatsMonitoringRedaction.ContainsSecretMaterial(customerPayload)).IsFalse();
        var correlation = new NatsMonitoringCorrelation("monitor0001", "gateway link state observed");
        await Assert.That(correlation.CorrelationToken).IsEqualTo("monitor0001");
        await Assert.That(() => new NatsMonitoringCorrelation("NOT A TOKEN", "summary"))
            .Throws<ArgumentException>();
        var redacted = new NatsMonitoringCorrelation("monitor0001", $"context {jwt} trailing");
        await Assert.That(redacted.RedactedSummary.Contains("eyJ", StringComparison.Ordinal)).IsFalse();
        await Assert.That(redacted.RedactedSummary).Contains(NatsMonitoringRedaction.RedactedPlaceholder);

        // Redaction also bounds length.
        var longSummary = string.Concat(Enumerable.Repeat("x", 1000));
        await Assert.That(NatsMonitoringRedaction.Sanitize(longSummary).Length).IsEqualTo(256);
    }
}
