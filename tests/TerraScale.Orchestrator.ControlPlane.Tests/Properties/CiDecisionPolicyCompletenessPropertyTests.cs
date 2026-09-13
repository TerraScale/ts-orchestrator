using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class CiDecisionPolicyCompletenessPropertyTests
{
    private const int Cases = 1_000;
    private static readonly RunnerCapability[] EveryCapability =
    [
        RunnerCapability.Compile,
        RunnerCapability.Test,
        RunnerCapability.Sign,
        RunnerCapability.Promote,
        RunnerCapability.ProductionDeploy,
        RunnerCapability.ControlRecover,
    ];

    [Test]
    public async Task EveryForbiddenCrossZoneRunnerCapabilityIsRejectedFor1000Cases()
    {
        var first = UnderCulture("en-US", () => RunForbiddenCapabilities(0xC1C1_0001));

        await AssertCultures(first, () => RunForbiddenCapabilities(0xC1C1_0001));
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Coverage).IsEqualTo(16);
    }

    [Test]
    public async Task AllowedSameZoneCapabilitySupersetsDispatchExactIntentFor1000Cases()
    {
        var first = UnderCulture("en-US", () => RunAllowedSupersets(0xC1C1_0002));

        await AssertCultures(first, () => RunAllowedSupersets(0xC1C1_0002));
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Coverage).IsEqualTo(8);
    }

    [Test]
    public async Task CiRunnerValidationAndTrustBoundaryPrecedenceIsExactFor1000Cases()
    {
        var first = UnderCulture("en-US", () => RunPrecedence(0xC1C1_0003));

        await AssertCultures(first, () => RunPrecedence(0xC1C1_0003));
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Coverage).IsEqualTo(11);
        await Assert.That(first.Outcomes).IsEqualTo(8);
    }

    [Test]
    public async Task UndefinedJobZoneAndCapabilityEnumsFailClosedFor1000Cases()
    {
        var first = UnderCulture("en-US", () => RunUndefinedEnums(0xC1C1_0004));

        await AssertCultures(first, () => RunUndefinedEnums(0xC1C1_0004));
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Coverage).IsEqualTo(10);
    }

    private static Summary RunForbiddenCapabilities(ulong seed)
    {
        var generator = new Generator(seed);
        var matrix = Enum.GetValues<JobKind>().Where(static value => value != JobKind.Unspecified)
            .SelectMany(kind => EveryCapability.Except(Policy(kind).Capabilities).Select(capability => (kind, capability)))
            .ToArray();
        Require(matrix.Length == 16, "forbidden-matrix", -1);
        var coverage = new HashSet<(JobKind Kind, RunnerCapability Forbidden)>();
        var outcomes = new HashSet<DeliveryErrorCode>();
        ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var (kind, forbidden) = matrix[index % matrix.Length];
            var policy = Policy(kind);
            var required = policy.Capabilities.Take(1).ToArray();
            var runnerCapabilities = required.Append(forbidden).ToArray();
            var job = Job(index, kind, policy.Zone, required);
            var runner = Runner($"runner-{index}-{generator.Next(1_000_000)}", policy.Zone, 50, runnerCapabilities);

            var decision = DeliveryEngine.DecideJob(job, [runner], 96);

            RequireHeld(decision, job, DeliveryErrorCode.TrustZoneDenied, "forbidden", index);
            coverage.Add((kind, forbidden));
            outcomes.Add(decision.Errors.Single().Code);
            digest = Mix(digest, forbidden.ToString(), job.Generation);
        }
        return new(Cases, coverage.Count, outcomes.Count, digest);
    }

    private static Summary RunAllowedSupersets(ulong seed)
    {
        var generator = new Generator(seed);
        var coverage = new HashSet<(JobKind Kind, RunnerCapability Required)>();
        ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var kind = (JobKind)(1 + index % 4);
            var policy = Policy(kind);
            var required = policy.Capabilities[(index / 4) % policy.Capabilities.Length];
            var job = Job(index, kind, policy.Zone, [required]);
            var selected = $"a-{index}-{generator.Next(1_000_000)}";
            RunnerEvidence[] runners =
            [
                Runner($"z-{index}", policy.Zone, 50, policy.Capabilities),
                Runner(selected, policy.Zone, 50, policy.Capabilities.Reverse().ToArray()),
                Runner($"poison-{index}", policy.Zone, 50, policy.Capabilities.Append(Forbidden(policy.Zone)).ToArray()),
            ];
            var rotated = Rotate(runners, generator.Next(runners.Length));

            var decision = DeliveryEngine.DecideJob(job, rotated, 96);

            RequireDispatch(decision, job, selected, "allowed-superset", index);
            coverage.Add((kind, required));
            digest = Mix(digest, selected, job.Generation);
        }
        return new(Cases, coverage.Count, 1, digest);
    }

    private static Summary RunPrecedence(ulong seed)
    {
        var generator = new Generator(seed);
        var coverage = new HashSet<int>();
        var outcomes = new HashSet<string>(StringComparer.Ordinal);
        ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var mode = index % 11;
            var job = Job(index, JobKind.TrustedBuild, TrustZone.TrustedBuild, [RunnerCapability.Compile]);
            var valid = Runner($"runner-{index}-{generator.Next(1_000_000)}", TrustZone.TrustedBuild, 50,
                RunnerCapability.Compile);
            DeliveryDecision decision;
            DeliveryErrorCode? expected;
            switch (mode)
            {
                case 0:
                    job = Job(index, JobKind.TrustedBuild, TrustZone.TrustedBuild, [RunnerCapability.Compile],
                        generation: 0, attempt: 4, maximumAttempts: 3, retry: false);
                    decision = DeliveryEngine.DecideJob(job, [valid], 96); expected = DeliveryErrorCode.InvalidInput; break;
                case 1:
                    job = Job(index, JobKind.TrustedBuild, TrustZone.TrustedBuild, [RunnerCapability.Compile],
                        attempt: 4, maximumAttempts: 3, retry: false);
                    decision = DeliveryEngine.DecideJob(job, [valid], 96); expected = DeliveryErrorCode.RetryDenied; break;
                case 2:
                    job = Job(index, JobKind.TrustedBuild, TrustZone.TrustedBuild, [RunnerCapability.Compile],
                        attempt: 4, maximumAttempts: 3, retry: true);
                    decision = DeliveryEngine.DecideJob(job, [valid], 96); expected = DeliveryErrorCode.AttemptsExhausted; break;
                case 3:
                    job = Job(index, JobKind.TrustedBuild, TrustZone.TrustedBuild, [RunnerCapability.ControlRecover]);
                    decision = DeliveryEngine.DecideJob(job,
                        [Runner($"undefined-{index}", (TrustZone)int.MaxValue, 50, (RunnerCapability)int.MaxValue)], 96);
                    expected = DeliveryErrorCode.TrustZoneDenied; break;
                case 4:
                    decision = DeliveryEngine.DecideJob(job,
                        [Runner($"undefined-{index}", TrustZone.TrustedBuild, 50, (RunnerCapability)int.MaxValue)], 96);
                    expected = DeliveryErrorCode.InvalidInput; break;
                case 5:
                    decision = DeliveryEngine.DecideJob(job,
                        [valid, Runner(valid.Runner.Value, TrustZone.TrustedBuild, 50, RunnerCapability.Compile)], 96);
                    expected = DeliveryErrorCode.DuplicateEvidence; break;
                case 6:
                    decision = DeliveryEngine.DecideJob(job,
                        [Runner($"stale-{index}", TrustZone.TrustedBuild, 9, RunnerCapability.Compile, RunnerCapability.ControlRecover)], 96);
                    expected = DeliveryErrorCode.RunnerStale; break;
                case 7:
                    decision = DeliveryEngine.DecideJob(job,
                        [Runner($"wrong-{index}", TrustZone.UntrustedProduct, 50, RunnerCapability.Compile, RunnerCapability.ControlRecover)], 96);
                    expected = DeliveryErrorCode.TrustZoneDenied; break;
                case 8:
                    decision = DeliveryEngine.DecideJob(job,
                        [Runner($"overprivileged-{index}", TrustZone.TrustedBuild, 50,
                            RunnerCapability.Compile, RunnerCapability.ProductionDeploy)], 96);
                    expected = DeliveryErrorCode.TrustZoneDenied; break;
                case 9:
                    job = Job(index, JobKind.TrustedBuild, TrustZone.TrustedBuild, [RunnerCapability.Compile, RunnerCapability.Test]);
                    decision = DeliveryEngine.DecideJob(job, [valid], 96); expected = DeliveryErrorCode.CapabilityMissing; break;
                default:
                    decision = DeliveryEngine.DecideJob(job, [valid], 96); expected = null; break;
            }

            string outcome;
            if (expected is { } code)
            {
                RequireHeld(decision, job, code, "precedence", index);
                outcome = code.ToString();
            }
            else
            {
                RequireDispatch(decision, job, valid.Runner.Value, "precedence", index);
                outcome = DeliveryAction.Dispatch.ToString();
            }
            outcomes.Add(outcome);
            coverage.Add(mode);
            digest = Mix(digest, outcome, job.Generation);
        }
        return new(Cases, coverage.Count, outcomes.Count, digest);
    }

    private static Summary RunUndefinedEnums(ulong seed)
    {
        var generator = new Generator(seed);
        var coverage = new HashSet<int>();
        var outcomes = new HashSet<DeliveryErrorCode>();
        ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var mode = index % 10;
            var kind = mode switch { 0 => JobKind.Unspecified, 1 => (JobKind)int.MaxValue, _ => JobKind.TrustedBuild };
            var jobZone = mode switch { 2 => TrustZone.Unspecified, 3 => (TrustZone)int.MaxValue, _ => TrustZone.TrustedBuild };
            var runnerZone = mode switch { 4 => TrustZone.Unspecified, 5 => (TrustZone)int.MaxValue, _ => TrustZone.TrustedBuild };
            var jobCapability = mode switch
            {
                6 => RunnerCapability.Unspecified,
                7 => (RunnerCapability)int.MaxValue,
                _ => RunnerCapability.Compile,
            };
            var runnerCapability = mode switch
            {
                8 => RunnerCapability.Unspecified,
                9 => (RunnerCapability)int.MaxValue,
                _ => RunnerCapability.Compile,
            };
            var job = Job(index, kind, jobZone, [jobCapability]);
            var runner = Runner($"runner-{index}-{generator.Next(1_000_000)}", runnerZone, 50, runnerCapability);

            var decision = DeliveryEngine.DecideJob(job, [runner], 96);

            RequireHeld(decision, job, DeliveryErrorCode.InvalidInput, "undefined-enum", index);
            coverage.Add(mode);
            outcomes.Add(decision.Errors.Single().Code);
            digest = Mix(digest, mode.ToString(CultureInfo.InvariantCulture), job.Generation);
        }
        return new(Cases, coverage.Count, outcomes.Count, digest);
    }

    private static void RequireHeld(DeliveryDecision decision, JobRequest job, DeliveryErrorCode code, string family, int index)
    {
        Require(decision.Intents.Count == 1 && decision.Errors.Count == 1 && decision.Trace.Count == 1, family, index);
        Require(decision.Intents[0] is HoldDeliveryIntent hold && hold.Action == DeliveryAction.Hold && hold.Reason == code &&
            hold.Job == job.Job, family, index);
        var error = decision.Errors[0];
        Require(error.Code == code && error.Requirement == DeliveryRequirementCode.Inv005 && error.Job == job.Job, family, index);
        var trace = decision.Trace[0];
        Require(trace.Sequence == 1 && trace.Code == DeliveryTraceCode.Held && trace.Action == DeliveryAction.Hold,
            family, index);
    }

    private static void RequireDispatch(DeliveryDecision decision, JobRequest job, string runner, string family, int index)
    {
        Require(decision.Intents.Count == 1 && decision.Errors.Count == 0 && decision.Trace.Count == 1, family, index);
        Require(decision.Intents[0] is DispatchJobIntent intent && intent.Action == DeliveryAction.Dispatch &&
            intent.Pipeline == job.Pipeline && intent.Job == job.Job && intent.Runner.Value == runner && intent.Tree == job.Tree &&
            intent.Generation == job.Generation && intent.Attempt == job.Attempt && intent.Idempotency == job.Idempotency,
            family, index);
        var trace = decision.Trace[0];
        Require(trace.Sequence == 1 && trace.Code == DeliveryTraceCode.RunnerSelected && trace.Action == DeliveryAction.Dispatch,
            family, index);
    }

    private static (TrustZone Zone, RunnerCapability[] Capabilities) Policy(JobKind kind) => kind switch
    {
        JobKind.ProductValidation => (TrustZone.UntrustedProduct, [RunnerCapability.Compile, RunnerCapability.Test]),
        JobKind.TrustedBuild => (TrustZone.TrustedBuild,
            [RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign]),
        JobKind.Promotion => (TrustZone.ProductionRelease,
            [RunnerCapability.Promote, RunnerCapability.ProductionDeploy]),
        JobKind.ControlRecovery => (TrustZone.ControlRecovery, [RunnerCapability.ControlRecover]),
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    private static RunnerCapability Forbidden(TrustZone zone) => zone switch
    {
        TrustZone.UntrustedProduct => RunnerCapability.ProductionDeploy,
        TrustZone.TrustedBuild => RunnerCapability.ProductionDeploy,
        TrustZone.ProductionRelease => RunnerCapability.Sign,
        TrustZone.ControlRecovery => RunnerCapability.Compile,
        _ => throw new ArgumentOutOfRangeException(nameof(zone)),
    };

    private static JobRequest Job(int index, JobKind kind, TrustZone zone, RunnerCapability[] capabilities,
        long? generation = null, int attempt = 1, int maximumAttempts = 3, bool retry = false) =>
        new(new($"pipeline-{index}"), new($"job-{index}"), kind, new($"tree-{index}"), generation ?? index + 1L,
            attempt, maximumAttempts, new($"key-{index}"), [zone], capabilities, 10, 100, retry);

    private static RunnerEvidence Runner(string id, TrustZone zone, long sequence, params RunnerCapability[] capabilities) =>
        new(new(id), zone, sequence, true, capabilities);

    private static T[] Rotate<T>(T[] values, int offset) => values.Skip(offset).Concat(values.Take(offset)).ToArray();
    private static T UnderCulture<T>(string name, Func<T> action)
    {
        var before = CultureInfo.CurrentCulture;
        try { CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(name); return action(); }
        finally { CultureInfo.CurrentCulture = before; }
    }
    private static async Task AssertCultures<T>(T baseline, Func<T> action)
    {
        foreach (var culture in new[] { "tr-TR", "ar-SA", "ja-JP" })
            await Assert.That(UnderCulture(culture, action)).IsEqualTo(baseline);
    }
    private static void Require(bool condition, string family, int index)
    {
        if (!condition) throw new InvalidOperationException($"{family} failed at {index}.");
    }
    private static ulong Mix(ulong digest, string value, long number)
    {
        unchecked
        {
            foreach (var character in value) digest = (digest ^ character) * 1099511628211UL;
            return (digest ^ (ulong)number) * 1099511628211UL;
        }
    }
    private sealed record Summary(int Cases, int Coverage, int Outcomes, ulong Digest);
    private sealed class Generator(ulong seed)
    {
        private ulong _state = seed;
        public int Next(int maximum)
        {
            _state ^= _state << 13; _state ^= _state >> 7; _state ^= _state << 17;
            return (int)(_state % (uint)maximum);
        }
    }
}

