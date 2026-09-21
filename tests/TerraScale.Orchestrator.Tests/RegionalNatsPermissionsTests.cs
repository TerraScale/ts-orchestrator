using NATS.Client.Core;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;
using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Tests;

public sealed class RegionalNatsPermissionsTests
{
    [Test]
    public async Task Controller_runtime_is_pinned_to_its_region_consumers_and_reply_identity()
    {
        var publicKey = NKeys.PublicKeyFromSeed(NKeys.CreateUserSeed());
        var otherKey = NKeys.PublicKeyFromSeed(NKeys.CreateUserSeed());
        var plan = RegionalNatsPermissions.Create("gru", "controller-1", publicKey);
        foreach (var subject in new[]
                 {
                     "$JS.API.CONSUMER.INFO.CELL_SPEC.gitops_cell_spec_controller-1",
                     "$JS.API.CONSUMER.MSG.NEXT.CELL_EVENTS.runtime_startup",
                     "$JS.API.STREAM.INFO.CELL_EVENTS",
                     "$JS.API.STREAM.INFO.OBJ_ORCH_PROTOCOL_PACKAGE",
                     "$JS.API.STREAM.MSG.GET.OBJ_ORCH_PROTOCOL_PACKAGE",
                     "$JS.API.CONSUMER.CREATE.KV_ORCH_DELIVERY.status",
                     "$JS.FC.KV_ORCH_DELIVERY.status.reply",
                     "ts.orch.v2.gru.query.status",
                     "ts.orch.v2.gru.query.members",
                     "ts.orch.v2.gru.query.health.controller-1",
                     "$SRV.INFO.terrascale_orchestrator_gru",
                     NatsSubjectTaxonomy.HostAgentCommandSubject("gru", "host-2", "report-" + new string('a', 32)),
                 })
            await Assert.That(Allows(plan.Publish, subject)).IsTrue().Because(subject);

        foreach (var subject in new[]
                 {
                     "$JS.API.CONSUMER.INFO.CELL_SPEC.gitops_cell_spec_controller-2",
                     "$JS.API.STREAM.CREATE.CELL_EVENTS",
                     "$JS.API.STREAM.UPDATE.KV_ORCH_RUNTIME",
                     "$JS.API.DIRECT.GET.KV_ORCH_OPERATIONS",
                     "$JS.API.DIRECT.GET.KV_ORCH_OPERATION_PROOFS",
                     "$JS.API.STREAM.MSG.GET.KV_ORCH_OPERATIONS",
                     "$JS.API.CONSUMER.CREATE.KV_ORCH_OPERATION_PROOFS.evil",
                     "$JS.API.CONSUMER.CREATE.KV_ORCH_NODE_ENROLLMENTS.evil",
                     "$O.ORCH_PROTOCOL_PACKAGE.C.chunk",
                     "$O.ORCH_PROTOCOL_PACKAGE.M.metadata",
                     "ts.orch.v2.fra.desired.anything",
                     "ts.orch.v2.gru.query.unknown",
                     "ts.orch.v2.global.release.ci.forgejo",
                 })
            await Assert.That(Allows(plan.Publish, subject)).IsFalse().Because(subject);

        await Assert.That(Allows(plan.Subscribe,
            NatsSubjectTaxonomy.ControllerInboxPrefix("gru", publicKey) + ".reply")).IsTrue();
        foreach (var subject in new[]
                 {
                     NatsSubjectTaxonomy.ControllerInboxPrefix("gru", otherKey) + ".reply",
                     $"ts.orch.v2.gru.command.journal.reply.{otherKey}.nonce",
                     $"ts.orch.v2.gru.command.runtime-lifecycle.reply.{otherKey}.nonce",
                     "ts.orch.v2.sfo.query.status",
                     "$KV.ORCH_OPERATIONS.operation",
                     "$KV.ORCH_OPERATION_PROOFS.proof",
                 })
            await Assert.That(Allows(plan.Subscribe, subject)).IsFalse().Because(subject);
    }

    [Test]
    [Arguments("gru.*", "controller-1", "UABC")]
    [Arguments("gru", "controller.*", "UABC")]
    [Arguments("gru", "controller-1", "UABC.>")]
    public async Task Permission_parameters_cannot_introduce_wildcards(string cell, string instance, string key) =>
        await Assert.That(() => RegionalNatsPermissions.Create(cell, instance, key)).Throws<ArgumentException>();

    private static bool Allows(IEnumerable<string> patterns, string subject)
    {
        SubjectGrammarLimits.TryCreate(2048, 64, 512, 32, out var limits);
        if (!ConcreteSubject.TryParse(subject, limits!, out var concrete, out _)) return false;
        return patterns.Any(pattern => SubjectPermissionPattern.TryParse(pattern, limits!, out var parsed, out _) &&
                                       parsed!.Matches(concrete));
    }
}
