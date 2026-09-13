using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.ControlPlane.Tests.Properties;
using System.Reflection;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class CiAudit3CounterexampleTests
{
    [Test]
    public async Task Accepted_dispatch_binds_exact_job_policy_and_selected_runner_evidence()
    {
        var product = Job(JobKind.ProductValidation, TrustZone.UntrustedProduct,
            [RunnerCapability.Compile]);
        var build = Job(JobKind.TrustedBuild, TrustZone.TrustedBuild,
            [RunnerCapability.Compile]);
        var productRunner = new RunnerEvidence(new RunnerId("shared-runner"), TrustZone.UntrustedProduct,
            20, true, [RunnerCapability.Compile]);
        var buildRunner = new RunnerEvidence(new RunnerId("shared-runner"), TrustZone.TrustedBuild,
            80, true, [RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign]);

        var productIntent = (DispatchJobIntent)DeliveryEngine.DecideJob(product, [productRunner], 96).Intents.Single();
        var buildIntent = (DispatchJobIntent)DeliveryEngine.DecideJob(build, [buildRunner], 96).Intents.Single();

        await Assert.That(CiDispatchFingerprint.Create(productIntent)).IsNotEqualTo(CiDispatchFingerprint.Create(buildIntent));
    }

    [Test]
    public async Task Dispatch_retains_every_exact_request_and_selected_evidence_field()
    {
        var zones = new[] { TrustZone.TrustedBuild };
        var required = new[] { RunnerCapability.Compile, RunnerCapability.Test };
        var runnerCapabilities = new[] { RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign };
        var request = new JobRequest(new("pipeline-exact"), new("job-exact"), JobKind.TrustedBuild,
            new("tree-exact"), 71, 2, 4, new("key-exact"), zones, required, 20, 90, true);
        var selected = new RunnerEvidence(new("runner-exact"), TrustZone.TrustedBuild, 33, true, runnerCapabilities);

        var intent = (DispatchJobIntent)DeliveryEngine.DecideJob(request, [selected], 97).Intents.Single();

        await Assert.That(ReferenceEquals(intent.Request, request)).IsTrue();
        await Assert.That(ReferenceEquals(intent.SelectedRunnerEvidence, selected)).IsTrue();
        await Assert.That(intent.MaximumIdentityLength).IsEqualTo(97);
        await Assert.That(ReferenceEquals(intent.Request.Pipeline, request.Pipeline)).IsTrue();
        await Assert.That(ReferenceEquals(intent.Request.Job, request.Job)).IsTrue();
        await Assert.That(intent.Request.Kind).IsEqualTo(request.Kind);
        await Assert.That(ReferenceEquals(intent.Request.Tree, request.Tree)).IsTrue();
        await Assert.That(intent.Request.Generation).IsEqualTo(71);
        await Assert.That(intent.Request.Attempt).IsEqualTo(2);
        await Assert.That(intent.Request.MaximumAttempts).IsEqualTo(4);
        await Assert.That(ReferenceEquals(intent.Request.Idempotency, request.Idempotency)).IsTrue();
        await Assert.That(intent.Request.AllowedZones.SequenceEqual(zones)).IsTrue();
        await Assert.That(intent.Request.RequiredCapabilities.SequenceEqual(required)).IsTrue();
        await Assert.That(intent.Request.MinimumRunnerSequence).IsEqualTo(20);
        await Assert.That(intent.Request.MaximumRunnerSequence).IsEqualTo(90);
        await Assert.That(intent.Request.RetryAuthorized).IsTrue();
        await Assert.That(ReferenceEquals(intent.SelectedRunnerEvidence.Runner, selected.Runner)).IsTrue();
        await Assert.That(intent.SelectedRunnerEvidence.Zone).IsEqualTo(TrustZone.TrustedBuild);
        await Assert.That(intent.SelectedRunnerEvidence.Sequence).IsEqualTo(33);
        await Assert.That(intent.SelectedRunnerEvidence.Available).IsTrue();
        await Assert.That(intent.SelectedRunnerEvidence.Capabilities.SequenceEqual(runnerCapabilities)).IsTrue();
        await Assert.That(ReferenceEquals(intent.Pipeline, request.Pipeline)).IsTrue();
        await Assert.That(ReferenceEquals(intent.Job, request.Job)).IsTrue();
        await Assert.That(ReferenceEquals(intent.Runner, selected.Runner)).IsTrue();
        await Assert.That(ReferenceEquals(intent.Tree, request.Tree)).IsTrue();
        await Assert.That(ReferenceEquals(intent.Idempotency, request.Idempotency)).IsTrue();

        zones[0] = TrustZone.UntrustedProduct;
        required[0] = RunnerCapability.ControlRecover;
        runnerCapabilities[0] = RunnerCapability.ProductionDeploy;
        await Assert.That(intent.Request.AllowedZones).IsEquivalentTo([TrustZone.TrustedBuild]);
        await Assert.That(intent.Request.RequiredCapabilities).IsEquivalentTo([RunnerCapability.Compile, RunnerCapability.Test]);
        await Assert.That(intent.SelectedRunnerEvidence.Capabilities).IsEquivalentTo(
            [RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign]);
    }

    [Test]
    public async Task Full_fingerprint_is_sensitive_to_each_new_context_family_and_semantic_replay_is_stable()
    {
        var baseline = Dispatch(JobKind.TrustedBuild, TrustZone.TrustedBuild, 50,
            [RunnerCapability.Compile], [RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign], 96);
        var semanticReplay = Dispatch(JobKind.TrustedBuild, TrustZone.TrustedBuild, 50,
            [RunnerCapability.Compile], [RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign], 96);
        var variants = new[]
        {
            Dispatch(JobKind.ProductValidation, TrustZone.UntrustedProduct, 50,
                [RunnerCapability.Compile], [RunnerCapability.Compile, RunnerCapability.Test], 96),
            Dispatch(JobKind.TrustedBuild, TrustZone.TrustedBuild, 51,
                [RunnerCapability.Compile], [RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign], 96),
            Dispatch(JobKind.TrustedBuild, TrustZone.TrustedBuild, 50,
                [RunnerCapability.Test], [RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign], 96),
            Dispatch(JobKind.TrustedBuild, TrustZone.TrustedBuild, 50,
                [RunnerCapability.Compile], [RunnerCapability.Compile, RunnerCapability.Sign], 96),
            Dispatch(JobKind.TrustedBuild, TrustZone.TrustedBuild, 50,
                [RunnerCapability.Compile], [RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign], 97),
        };
        var fingerprint = CiDispatchFingerprint.Create(baseline);
        await Assert.That(CiDispatchFingerprint.Create(semanticReplay)).IsEqualTo(fingerprint);
        foreach (var variant in variants)
            await Assert.That(CiDispatchFingerprint.Create(variant)).IsNotEqualTo(fingerprint);
    }

    [Test]
    public async Task Every_job_kind_dispatches_exact_context_and_all_job_denials_emit_no_dispatch()
    {
        foreach (var tuple in new[]
        {
            (JobKind.ProductValidation, TrustZone.UntrustedProduct, RunnerCapability.Compile),
            (JobKind.TrustedBuild, TrustZone.TrustedBuild, RunnerCapability.Compile),
            (JobKind.Promotion, TrustZone.ProductionRelease, RunnerCapability.Promote),
            (JobKind.ControlRecovery, TrustZone.ControlRecovery, RunnerCapability.ControlRecover),
        })
        {
            var request = Job(tuple.Item1, tuple.Item2, [tuple.Item3]);
            var evidence = new RunnerEvidence(new("runner"), tuple.Item2, 50, true, [tuple.Item3]);
            var intent = (DispatchJobIntent)DeliveryEngine.DecideJob(request, [evidence], 96).Intents.Single();
            await Assert.That(ReferenceEquals(intent.Request, request)).IsTrue();
            await Assert.That(ReferenceEquals(intent.SelectedRunnerEvidence, evidence)).IsTrue();
        }

        var valid = Job(JobKind.TrustedBuild, TrustZone.TrustedBuild, [RunnerCapability.Compile]);
        var runner = new RunnerEvidence(new("runner"), TrustZone.TrustedBuild, 50, true, [RunnerCapability.Compile]);
        var denied = new[]
        {
            DeliveryEngine.DecideJob(Job(JobKind.TrustedBuild, TrustZone.TrustedBuild, [RunnerCapability.Compile], generation: 0), [runner], 96),
            DeliveryEngine.DecideJob(Job(JobKind.TrustedBuild, TrustZone.TrustedBuild, [RunnerCapability.Compile], attempt: 2, retry: false), [runner], 96),
            DeliveryEngine.DecideJob(Job(JobKind.TrustedBuild, TrustZone.TrustedBuild, [RunnerCapability.Compile], attempt: 4, maximumAttempts: 3, retry: true), [runner], 96),
            DeliveryEngine.DecideJob(Job(JobKind.TrustedBuild, TrustZone.TrustedBuild, [RunnerCapability.ControlRecover]), [runner], 96),
            DeliveryEngine.DecideJob(valid, [runner, runner], 96),
            DeliveryEngine.DecideJob(valid, [new(new("runner"), TrustZone.TrustedBuild, 9, true, [RunnerCapability.Compile])], 96),
            DeliveryEngine.DecideJob(valid, [new(new("runner"), TrustZone.UntrustedProduct, 50, true, [RunnerCapability.Compile])], 96),
            DeliveryEngine.DecideJob(Job(JobKind.TrustedBuild, TrustZone.TrustedBuild,
                [RunnerCapability.Compile, RunnerCapability.Test]), [runner], 96),
        };
        foreach (var decision in denied)
            await Assert.That(decision.Intents.OfType<DispatchJobIntent>()).IsEmpty();
    }

    [Test]
    public async Task Dispatch_construction_surface_is_closed()
    {
        var type = typeof(DispatchJobIntent);
        await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(static property => property.SetMethod?.IsPublic == true)).IsEmpty();
        await Assert.That(type.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(static method => method.Name == "Deconstruct")).IsEmpty();
        await Assert.That(type.Assembly.GetExportedTypes()
            .SelectMany(static exported => exported.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(method => !method.IsSpecialName && method.ReturnType == type)).IsEmpty();
        DispatchJobIntent? uninitialized = default;
        await Assert.That(uninitialized).IsNull();
    }

    private static JobRequest Job(JobKind kind, TrustZone zone, RunnerCapability[] capabilities,
        long generation = 7, int attempt = 1, int maximumAttempts = 3, bool retry = false) =>
        new(new PipelineId("pipeline"), new JobId("job"), kind, new TreeId("tree"), generation, attempt, maximumAttempts,
            new IdempotencyId("key"), [zone], capabilities, 10, 100, retry);

    private static DispatchJobIntent Dispatch(JobKind kind, TrustZone zone, long sequence,
        RunnerCapability[] required, RunnerCapability[] available, int maximumIdentityLength)
    {
        var request = Job(kind, zone, required);
        var evidence = new RunnerEvidence(new("runner"), zone, sequence, true, available);
        return (DispatchJobIntent)DeliveryEngine.DecideJob(request, [evidence], maximumIdentityLength).Intents.Single();
    }
}

