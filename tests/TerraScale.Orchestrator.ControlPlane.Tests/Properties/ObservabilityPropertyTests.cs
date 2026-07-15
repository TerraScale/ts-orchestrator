using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Observability;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class ObservabilityPropertyTests
{
    private const int Cases = 1000;

    [Test]
    public async Task Labels_metrics_generation_and_cardinality_follow_exact_oracle_for_1000_cases()
    {
        var identities = new HashSet<string>(StringComparer.Ordinal); var executed = 0;
        for (var seed = 1UL; seed <= Cases; seed++)
        {
            var variant = (int)(seed % 6); var request = ObservabilityData.Admission(seed, variant); identities.Add(request.Spec.OperationId.Value);
            var decision = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(request);
            var expected = variant switch { 0 => "AdmitTelemetryIntent", 3 => "HoldObservabilityIntent", _ => "DropTelemetryIntent" };
            Require(decision.Intent.GetType().Name == expected && decision.Authorized == (variant == 0), seed, "admission");
            if (variant == 0)
            {
                var subject = ((AdmitTelemetryIntent)decision.Intent).Spec;
                Require(subject.OperationId == request.Spec.OperationId && subject.TenantId == request.Spec.TenantId && subject.CellId == request.Spec.CellId &&
                    subject.ServiceId == request.Spec.ServiceId && subject.SignalId == request.Spec.SignalId && subject.MetricId == request.Spec.MetricId &&
                    subject.SchemaGeneration == request.Spec.SchemaGeneration && subject.SchemaDigest == request.Spec.SchemaDigest && subject.Labels.SequenceEqual(request.Spec.Labels), seed, "admission subject");
            }
            var code = variant switch { 1 => ObservabilityDecisionCode.CardinalityWithinBudget, 2 or 3 => ObservabilityDecisionCode.GenerationCurrent,
                4 => ObservabilityDecisionCode.SecretFree, 5 => ObservabilityDecisionCode.ScopeExact, _ => ObservabilityDecisionCode.LabelsBounded };
            Require(decision.Trace.Single(r => r.Code == code).Outcome == (variant == 3 ? ObservabilityDecisionOutcome.Held : variant == 0 ? ObservabilityDecisionOutcome.Passed : ObservabilityDecisionOutcome.Rejected), seed, "admission code"); executed++;
        }
        await Assert.That(executed).IsEqualTo(1000); await Assert.That(identities.Count).IsEqualTo(1000);
    }

    [Test]
    public async Task Dashboard_projection_generation_ownership_and_drift_follow_exact_oracle_for_1000_cases()
    {
        var changeNames = new[] { "CreateGrafanaResource", "UpdateGrafanaResource", "DeleteGrafanaResource", "ReportGrafanaDrift" }; var executed = 0;
        for (var seed = 1UL; seed <= Cases; seed++)
        {
            var variant = (int)(seed % 5); var decision = ObservabilityDecisionEngine.EvaluateGrafanaProjection(ObservabilityData.Projection(seed, variant));
            if (variant < 4)
            {
                Require(decision.Authorized && decision.Intent is ProjectGrafanaIntent p && p.Changes.Single().GetType().Name == changeNames[variant], seed, "projection");
                if (variant == 3) Require(((ReportGrafanaDrift)((ProjectGrafanaIntent)decision.Intent).Changes.Single()).Resource.Ownership ==
                    (seed % 2 == 0 ? GrafanaOwnership.Unmanaged : GrafanaOwnership.Conflicting), seed, "drift ownership");
                Require(decision.Trace.Single(r => r.Code == ObservabilityDecisionCode.ProjectionExact).Outcome == ObservabilityDecisionOutcome.Passed, seed, "projection code");
            }
            else Require(!decision.Authorized && decision.Intent is HoldObservabilityIntent && decision.Trace.Single(r => r.Code == ObservabilityDecisionCode.EvidenceComplete).Outcome == ObservabilityDecisionOutcome.Rejected, seed, "projection stale");
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Alert_generation_dedupe_scope_and_operation_follow_exact_oracle_for_1000_cases()
    {
        var executed = 0; for (var seed = 1UL; seed <= Cases; seed++)
        {
            var variant = (int)(seed % 6); var decision = ObservabilityDecisionEngine.EvaluateAlertRouting(ObservabilityData.Alert(seed, variant));
            Require(decision.Authorized == (variant == 0) && decision.Intent.GetType().Name == (variant == 0 ? "RouteAlertIntent" : "HoldObservabilityIntent"), seed, "alert");
            if (variant == 0) { var route = (RouteAlertIntent)decision.Intent; var request = ObservabilityData.Alert(seed, variant); Require(route.AlertId == request.Alert.AlertId && route.ContactId == request.ContactId && route.Contact == request.Contact, seed, "alert subject"); }
            var code = variant switch { 1 => ObservabilityDecisionCode.DedupeUnique, 2 or 3 => ObservabilityDecisionCode.GenerationCurrent, 4 => ObservabilityDecisionCode.OperationExact, 5 => ObservabilityDecisionCode.EvidenceComplete, _ => ObservabilityDecisionCode.ScopeExact };
            Require(decision.Trace.Single(r => r.Code == code).Outcome == (variant == 3 ? ObservabilityDecisionOutcome.Held : variant == 1 ? ObservabilityDecisionOutcome.Held : variant == 0 ? ObservabilityDecisionOutcome.Passed : ObservabilityDecisionOutcome.Rejected), seed, "alert code"); executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Regional_health_scope_persistence_retention_ha_spool_and_evidence_follow_exact_oracle_for_1000_cases()
    {
        var identities = new HashSet<string>(StringComparer.Ordinal); var executed = 0;
        for (var seed = 1UL; seed <= Cases; seed++)
        {
            var variant = (int)(seed % 13); var request = ObservabilityData.Regional(seed, variant); identities.Add(request.OperationId.Value);
            var decision = ObservabilityDecisionEngine.EvaluateRegionalHealth(request);
            Require(decision.Intent is AggregateRegionalTelemetryIntent && decision.Authorized == (variant == 0), seed, "regional action");
            var intent = (AggregateRegionalTelemetryIntent)decision.Intent;
            Require(ReferenceEquals(intent.Request, request) && intent.OperationId == request.OperationId && intent.Findings.Count == 3, seed, "regional subject");

            var targetCode = variant switch
            {
                4 => ObservabilityDecisionCode.PersistenceExact,
                5 => ObservabilityDecisionCode.RetentionExact,
                6 => ObservabilityDecisionCode.IngestHaSatisfied,
                7 => ObservabilityDecisionCode.QueryHaSatisfied,
                8 => ObservabilityDecisionCode.SpoolWithinPolicy,
                9 or 10 => ObservabilityDecisionCode.EvidenceComplete,
                _ => ObservabilityDecisionCode.ScopeExact,
            };
            var outcome = variant switch
            {
                0 => ObservabilityDecisionOutcome.Passed,
                1 or 2 or 3 or 4 or 5 => ObservabilityDecisionOutcome.Rejected,
                _ => ObservabilityDecisionOutcome.Held,
            };
            Require(decision.Trace.Single(r => r.Code == targetCode).Outcome == outcome, seed, "regional code");

            var expectedTrace = variant switch
            {
                0 => new[] { ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed },
                1 or 2 or 3 => [ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Rejected, ObservabilityDecisionOutcome.Rejected, ObservabilityDecisionOutcome.Rejected, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held],
                4 => [ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Rejected, ObservabilityDecisionOutcome.Rejected, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held],
                5 => [ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Rejected, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Rejected, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held],
                6 => [ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed],
                7 => [ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Passed],
                8 => [ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Held],
                9 or 10 => [ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held],
                _ => [ObservabilityDecisionOutcome.Passed, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held, ObservabilityDecisionOutcome.Held],
            };
            ObservabilityDecisionCode[] expectedCodes = [ObservabilityDecisionCode.EvidenceComplete, ObservabilityDecisionCode.ScopeExact,
                ObservabilityDecisionCode.PersistenceExact, ObservabilityDecisionCode.RetentionExact, ObservabilityDecisionCode.IngestHaSatisfied,
                ObservabilityDecisionCode.QueryHaSatisfied, ObservabilityDecisionCode.SpoolWithinPolicy];
            Require(decision.Trace.Select(r => r.Code).SequenceEqual(expectedCodes) && decision.Trace.Select(r => r.Outcome).SequenceEqual(expectedTrace), seed, "regional trace precedence");

            Require(intent.Findings.Select(f => f.Signal).SequenceEqual(Enum.GetValues<TelemetrySignalKind>()), seed, "regional finding order");
            var expectedMetric = variant switch
            {
                1 or 2 or 3 or 4 or 5 or 9 or 10 or 11 or 12 => (TelemetryAvailability.Unknown, TelemetryAvailability.Unknown, SpoolStatus.Unknown, false),
                6 => (TelemetryAvailability.Unavailable, TelemetryAvailability.Available, SpoolStatus.Healthy, false),
                7 => (TelemetryAvailability.Available, TelemetryAvailability.Unavailable, SpoolStatus.Healthy, false),
                _ => (TelemetryAvailability.Available, TelemetryAvailability.Available, SpoolStatus.Healthy, false),
            };
            var metric = intent.Findings.Single(f => f.Signal == TelemetrySignalKind.Metric);
            Require((metric.Ingest, metric.Query, metric.Spool, metric.DataLoss) == expectedMetric, seed, "regional metric finding");
            foreach (var signal in new[] { TelemetrySignalKind.Log, TelemetrySignalKind.Trace })
            {
                var finding = intent.Findings.Single(f => f.Signal == signal);
                Require((finding.Ingest, finding.Query, finding.Spool, finding.DataLoss) ==
                    (TelemetryAvailability.Available, TelemetryAvailability.Available, SpoolStatus.Healthy, false), seed, $"regional {signal} finding");
            }
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000); await Assert.That(identities.Count).IsEqualTo(1000);
    }

    [Test]
    public async Task Regional_health_permutation_and_culture_replay_is_stable_for_1000_cases()
    {
        var cultures = new[] { "tr-TR", "ar-SA", "ja-JP" }; var executed = 0;
        for (var seed = 1UL; seed <= Cases; seed++)
        {
            var previous = CultureInfo.CurrentCulture; var previousUi = CultureInfo.CurrentUICulture;
            try
            {
                var variant = (int)(seed % 13);
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("en-US"); CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("en-US");
                var a = ObservabilityDecisionEngine.EvaluateRegionalHealth(ObservabilityData.Regional(seed, variant, false));
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultures[seed % 3]); CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(cultures[seed % 3]);
                var b = ObservabilityDecisionEngine.EvaluateRegionalHealth(ObservabilityData.Regional(seed, variant, true));
                Require(SerializeRegional(a) == SerializeRegional(b), seed, "regional permutation and culture"); executed++;
            }
            finally { CultureInfo.CurrentCulture = previous; CultureInfo.CurrentUICulture = previousUi; }
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Duplicate_and_conflicting_evidence_fail_closed_for_1000_cases()
    {
        var executed = 0; for (var seed = 1UL; seed <= Cases; seed++)
        {
            if (seed % 2 == 0)
            {
                var request = ObservabilityData.Admission(seed, 0); var label = request.Spec.Labels[0];
                Require(Throws<ArgumentException>(() => new TelemetryAdmissionSpec(request.Spec.OperationId, request.Spec.TenantId, request.Spec.CellId,
                    request.Spec.ServiceId, request.Spec.SignalId, request.Spec.MetricId, request.Spec.SignalKind, request.Spec.SchemaGeneration,
                    request.Spec.SchemaDigest, new(2), [label, label])), seed, "duplicate labels");
            }
            else
            {
                var decision = ObservabilityDecisionEngine.EvaluateAlertRouting(ObservabilityData.Alert(seed, 5));
                Require(!decision.Authorized && decision.Trace.Single(r => r.Code == ObservabilityDecisionCode.EvidenceComplete).Outcome == ObservabilityDecisionOutcome.Rejected, seed, "conflicting alert evidence");
            }
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Permutation_culture_replay_is_stable_and_telemetry_cannot_authorize_mutation_for_1000_cases()
    {
        var cultures = new[] { "en-US", "tr-TR", "ar-SA", "ja-JP" }; var executed = 0;
        for (var seed = 1UL; seed <= Cases; seed++)
        {
            var previous = CultureInfo.CurrentCulture;
            try { CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultures[seed % 4]);
                var a = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(ObservabilityData.Admission(seed, 0, false));
                var b = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(ObservabilityData.Admission(seed, 0, true));
                Require(Serialize(a) == Serialize(b), seed, "permutation");
                Require(a.Intent.GetType() == typeof(AdmitTelemetryIntent), seed, "telemetry authority separation"); executed++; }
            finally { CultureInfo.CurrentCulture = previous; }
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Construction_is_closed_and_strict_pinned_replay_is_input_sensitive()
    {
        await Assert.That(typeof(ObservabilityDecision).GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length).IsEqualTo(0);
        await Assert.That(typeof(ObservabilityDecision).GetMethods(BindingFlags.Public | BindingFlags.Static).Count(m => m.ReturnType == typeof(ObservabilityDecision) && !m.IsSpecialName)).IsEqualTo(0);
        await Assert.That(typeof(ObservabilityIntent).Assembly.GetTypes().Where(t => typeof(ObservabilityIntent).IsAssignableFrom(t)).SelectMany(t => t.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).Count()).IsEqualTo(0);
        Type[] forbiddenAuthorityTypes = [typeof(TerraScale.Orchestrator.ControlPlane.Authority.AuthorityIntent), typeof(TerraScale.Orchestrator.ControlPlane.Operations.OperationIntent),
            typeof(TerraScale.Orchestrator.ControlPlane.Providers.ProviderMutationIntent), typeof(TerraScale.Orchestrator.ControlPlane.Authority.MutationAuthorityPermit),
            typeof(TerraScale.Orchestrator.ControlPlane.Authority.AuthorityDecision), typeof(TerraScale.Orchestrator.ControlPlane.Providers.ProviderAuthorizationDecision)];
        var intentTypes = typeof(ObservabilityIntent).Assembly.GetTypes().Where(t => typeof(ObservabilityIntent).IsAssignableFrom(t)).ToArray();
        await Assert.That(intentTypes.Any(t => forbiddenAuthorityTypes.Any(f => f.IsAssignableFrom(t)) ||
            t.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static).Any(p => forbiddenAuthorityTypes.Any(f => f.IsAssignableFrom(p.PropertyType))) ||
            t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static).Any(m => forbiddenAuthorityTypes.Any(f => f.IsAssignableFrom(m.ReturnType))))).IsFalse();
        foreach (var entry in ObservabilityCorpus.Load())
        {
            var (actual, fingerprint) = EvaluateEntry(entry);
            Require(actual == entry.Expected, entry.Seed, entry.Id); Require(fingerprint == ExpectedFingerprint(entry), entry.Seed, "fingerprint");
            Require(EvaluateEntry(entry with { Seed = entry.Seed + 1 }).Item2 != fingerprint, entry.Seed, "mutated seed sensitivity");
        }
        var corpus = ObservabilityCorpus.Load();
        await Assert.That(corpus.Count).IsEqualTo(30);
        await Assert.That(corpus.Where(x => x.Kind == "admission").Select(x => x.Variant).Order().SequenceEqual(Enumerable.Range(0, 6))).IsTrue();
        await Assert.That(corpus.Where(x => x.Kind == "projection").Select(x => x.Variant).Order().SequenceEqual(Enumerable.Range(0, 5))).IsTrue();
        await Assert.That(corpus.Where(x => x.Kind == "alert").Select(x => x.Variant).Order().SequenceEqual(Enumerable.Range(0, 6))).IsTrue();
        await Assert.That(corpus.Where(x => x.Kind == "regional").Select(x => x.Variant).Order().SequenceEqual(Enumerable.Range(0, 13))).IsTrue();
    }

    [Test]
    public async Task Replay_reader_and_parser_reject_byte_shape_identity_seed_and_vocabulary_drift()
    {
        await Assert.That(ObservabilityCorpus.ReadBounded(new MemoryStream(new byte[8192])).Length).IsEqualTo(8192);
        await Assert.That(Fails(() => ObservabilityCorpus.ReadBounded(new MemoryStream(new byte[8193])))).IsTrue();
        await Assert.That(ObservabilityCorpus.Parse(System.Text.Encoding.UTF8.GetBytes(Entry(new string('a', 64), "1000000", "admission", 0, "AdmitTelemetryIntent")), false).Count).IsEqualTo(1);
        var valid = Entry("exact-byte-bound", "1", "admission", 0, "AdmitTelemetryIntent");
        var exactBytes = System.Text.Encoding.UTF8.GetBytes(valid + new string(' ', 8192 - System.Text.Encoding.UTF8.GetByteCount(valid)));
        await Assert.That(ObservabilityCorpus.Parse(exactBytes, false).Count).IsEqualTo(1);
        await Assert.That(Fails(() => ObservabilityCorpus.Parse(exactBytes.Append((byte)' ').ToArray(), false))).IsTrue();
        var invalid = new[] { "{}", "{/*x*/\"schema\":\"terrascale.observability-replay.v1\",\"entries\":[]}",
            "{\"schema\":\"terrascale.observability-replay.v1\",\"entries\":[],}",
            "{\"schema\":\"terrascale.observability-replay.v1\",\"entries\":[]} trailing", "{\"schema\":\"terrascale.observability-replay.v1\",\"entries\":[[[[[1]]]]]}",
            Entry("bad id", "1", "admission", 0, "AdmitTelemetryIntent"), Entry(new string('a', 65), "1", "admission", 0, "AdmitTelemetryIntent"),
            Entry("-bad", "1", "admission", 0, "AdmitTelemetryIntent"), Entry("bad-", "1", "admission", 0, "AdmitTelemetryIntent"), Entry("bad--id", "1", "admission", 0, "AdmitTelemetryIntent"), Entry("Bad", "1", "admission", 0, "AdmitTelemetryIntent"), Entry("bad\nid", "1", "admission", 0, "AdmitTelemetryIntent"),
            Entry("x", "0", "admission", 0, "AdmitTelemetryIntent"), Entry("x", "-1", "admission", 0, "AdmitTelemetryIntent"), Entry("x", "\"1\"", "admission", 0, "AdmitTelemetryIntent"), Entry("x", "1000001", "admission", 0, "AdmitTelemetryIntent"),
            Entry("x", "1", "unknown", 0, "AdmitTelemetryIntent"), Entry("x", "1", "admission", 0, "DropTelemetryIntent"),
            "{\"schema\":\"terrascale.observability-replay.v1\",\"entries\":[] ,\"extra\":1}",
            "{\"schema\":\"terrascale.observability-replay.v1\"}",
            "{\"schema\":1,\"entries\":[]}",
            "{\"schema\":\"terrascale.observability-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"kind\":\"admission\",\"variant\":0,\"expected\":\"AdmitTelemetryIntent\",\"extra\":1}]}",
            "{\"schema\":\"terrascale.observability-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"kind\":\"admission\",\"variant\":0}]}",
            "{\"schema\":\"terrascale.observability-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"kind\":\"admission\",\"variant\":\"0\",\"expected\":\"AdmitTelemetryIntent\"}]}",
            "{\"schema\":\"terrascale.observability-replay.v1\",\"entries\":[{\"id\":\"x\",\"id\":\"y\",\"seed\":1,\"kind\":\"admission\",\"variant\":0,\"expected\":\"AdmitTelemetryIntent\"}]}",
            "{\"schema\":\"terrascale.observability-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"kind\":\"admission\",\"variant\":0,\"expected\":\"AdmitTelemetryIntent\"},{\"id\":\"x\",\"seed\":2,\"kind\":\"admission\",\"variant\":0,\"expected\":\"AdmitTelemetryIntent\"}]}",
            "{\"schema\":\"terrascale.observability-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"kind\":\"admission\",\"variant\":0,\"expected\":\"AdmitTelemetryIntent\"},{\"id\":\"y\",\"seed\":1,\"kind\":\"admission\",\"variant\":0,\"expected\":\"AdmitTelemetryIntent\"}]}" };
        foreach (var json in invalid) await Assert.That(Fails(() => ObservabilityCorpus.Parse(System.Text.Encoding.UTF8.GetBytes(json), false))).IsTrue();
        var sixtyFour = "{\"schema\":\"terrascale.observability-replay.v1\",\"entries\":[" + string.Join(',', Enumerable.Range(1, 64).Select(i => $"{{\"id\":\"id-{i}\",\"seed\":{i},\"kind\":\"admission\",\"variant\":0,\"expected\":\"AdmitTelemetryIntent\"}}")) + "]}";
        await Assert.That(ObservabilityCorpus.Parse(System.Text.Encoding.UTF8.GetBytes(sixtyFour), false).Count).IsEqualTo(64);
        var sixtyFive = "{\"schema\":\"terrascale.observability-replay.v1\",\"entries\":[" + string.Join(',', Enumerable.Range(1, 65).Select(i => $"{{\"id\":\"id-{i}\",\"seed\":{i},\"kind\":\"admission\",\"variant\":0,\"expected\":\"AdmitTelemetryIntent\"}}")) + "]}";
        await Assert.That(Fails(() => ObservabilityCorpus.Parse(System.Text.Encoding.UTF8.GetBytes(sixtyFive), false))).IsTrue();
    }

    private static (string, string) AdmissionResult(ObservabilityEntry e) { var r = ObservabilityData.Admission(e.Seed, e.Variant); var d = ObservabilityDecisionEngine.EvaluateTelemetryAdmission(r); return (d.Intent.GetType().Name, $"{r.Spec.OperationId.Value}|{r.Spec.MetricId.Value}|{r.Spec.SchemaGeneration.Value}"); }
    private static (string, string) ProjectionResult(ObservabilityEntry e) { var r = ObservabilityData.Projection(e.Seed, e.Variant); var d = ObservabilityDecisionEngine.EvaluateGrafanaProjection(r); var name = d.Intent is ProjectGrafanaIntent p ? p.Changes.Single().GetType().Name : d.Intent.GetType().Name; return (name, $"{r.OperationId.Value}|{r.Generation.Value}|{r.CurrentSequence.Value}|{r.CurrentAcceptedGeneration.Value}|{r.CurrentAcceptedSequence.Value}|{string.Join(',', d.Trace.Select(x => $"{x.Code}:{x.Outcome}:{x.Observed}:{x.Required}"))}"); }
    private static (string, string) AlertResult(ObservabilityEntry e) { var r = ObservabilityData.Alert(e.Seed, e.Variant); var d = ObservabilityDecisionEngine.EvaluateAlertRouting(r); return (d.Intent.GetType().Name, $"{r.Alert.OperationId.Value}|{r.Alert.AlertId.Value}|{r.Alert.Generation.Value}"); }
    private static (string, string) RegionalResult(ObservabilityEntry e)
    {
        var r = ObservabilityData.Regional(e.Seed, e.Variant); var d = ObservabilityDecisionEngine.EvaluateRegionalHealth(r); var code = ObservabilityData.RegionalCode(e.Variant);
        var observations = string.Join(',', r.Observations.Where(o => o.Signal == TelemetrySignalKind.Metric).Select(o => $"{o.OperationId.Value}:{o.CellId.Value}:{o.Generation.Value}:{o.Sequence.Value}:{o.SchemaDigest.Sha256[0]}:{o.Persistence}:{o.Retention.Value}:{o.HealthyIngestReplicas}:{o.HealthyQueryReplicas}:{o.LocalSpoolBytes}"));
        return ($"{d.Intent.GetType().Name}|{d.Authorized}|{code}:{d.Trace.Single(x => x.Code == code).Outcome}", $"{r.OperationId.Value}|{r.CellId.Value}|{r.Generation.Value}|{r.CurrentSequence.Value}|{r.Observations.Count}|{observations}");
    }
    private static (string, string) EvaluateEntry(ObservabilityEntry e) => e.Kind switch { "admission" => AdmissionResult(e), "projection" => ProjectionResult(e), "alert" => AlertResult(e), "regional" => RegionalResult(e), _ => throw new InvalidDataException() };
    private static string ExpectedFingerprint(ObservabilityEntry e) => e.Kind switch { "admission" => $"operation-{e.Seed}|metric-{e.Seed}|{(e.Variant == 2 ? 999 + e.Seed : e.Variant == 3 ? 1001 + e.Seed : 1000 + e.Seed)}", "projection" => ExpectedProjectionFingerprint(e), "alert" => $"{(e.Variant == 4 ? "wrong" : "operation")}-{e.Seed}|alert-{e.Seed}|{(e.Variant == 2 ? 999 + e.Seed : e.Variant == 3 ? 1001 + e.Seed : 1000 + e.Seed)}", "regional" => ObservabilityData.ExpectedRegionalFingerprint(e.Seed, e.Variant), _ => throw new InvalidDataException() };
    private static string ExpectedProjectionFingerprint(ObservabilityEntry e)
    {
        var generation = 1000 + e.Seed;
        var evidence = e.Variant == 4
            ? $"EvidenceComplete:Rejected:{generation - 1}:{generation}"
            : "EvidenceComplete:Passed:1:1";
        var trace = $"{evidence},ProjectionGenerationNotRollback:Passed:{generation}:{generation},ProjectionSequenceNotRollback:Passed:9:9,ScopeExact:Passed:1:1,AccessExact:Passed:1:1,GenerationCurrent:Passed:1:1,OwnershipExact:Passed:1:1";
        if (e.Variant != 4)
        {
            var count = e.Variant is 1 or 3 ? 2UL : 1UL;
            trace += $",ProjectionExact:Passed:{count}:{count}";
        }
        return $"operation-{e.Seed}|{generation}|9|{generation}|9|{trace}";
    }
    private static string Entry(string id, string seed, string kind, int variant, string expected) => $"{{\"schema\":\"terrascale.observability-replay.v1\",\"entries\":[{{\"id\":\"{id}\",\"seed\":{seed},\"kind\":\"{kind}\",\"variant\":{variant},\"expected\":\"{expected}\"}}]}}";
    private static string Serialize(ObservabilityDecision d) => $"{d.Authorized}|{d.Intent.GetType().Name}|" + string.Join(';', d.Trace.Select(r => $"{r.Code}:{r.Outcome}:{r.Observed}:{r.Required}"));
    private static string SerializeRegional(ObservabilityDecision d) => Serialize(d) + "|" + string.Join(';', ((AggregateRegionalTelemetryIntent)d.Intent).Findings.Select(f => $"{f.Signal}:{f.Ingest}:{f.Query}:{f.Spool}:{f.DataLoss}"));
    private static void Require(bool condition, ulong seed, string property) { if (!condition) throw new InvalidOperationException($"{property} failed at seed {seed}."); }
    private static bool Fails(Action action) { try { action(); return false; } catch (Exception) { return true; } }
    private static bool Throws<T>(Action action) where T : Exception { try { action(); return false; } catch (T) { return true; } }
}

internal static class ObservabilityData
{
    private static ObservabilityDigest Digest(char value = 'a') => new(new string(value, 64));
    internal static TelemetryAdmissionRequest Admission(ulong seed, int variant, bool reverse = false)
    {
        var operation = new ObservabilityOperationId($"operation-{seed}"); var tenant = new ObservabilityTenantId($"tenant-{seed}"); var cell = new ObservabilityCellId($"cell-{seed}"); var generation = 1000 + seed;
        var labels = new[] { new TelemetryLabel(new("region"), new("gru")), new TelemetryLabel(new("service"), new("api")) }; var catalog = new[] {
            new TelemetryLabelCatalogEntry(new("region"), variant == 4 ? LabelClassification.SecretBearingForbidden : LabelClassification.BoundedPublic, new(2), [new ObservabilityLabelValue("gru")]),
            new TelemetryLabelCatalogEntry(new("service"), LabelClassification.BoundedPublic, new(2), [new ObservabilityLabelValue("api")]) };
        if (reverse) { Array.Reverse(labels); Array.Reverse(catalog); }
        var observedGeneration = variant == 2 ? generation - 1 : variant == 3 ? generation + 1 : generation;
        var spec = new TelemetryAdmissionSpec(operation, tenant, cell, new($"service-{seed}"), new($"signal-{seed}"), new($"metric-{seed}"), TelemetrySignalKind.Metric, new(observedGeneration), Digest(), new(2), labels);
        var cardinality = new CardinalityEvidence(operation, tenant, cell, spec.SignalId, new(observedGeneration), Digest(), new(9), EvidenceCompleteness.Complete, variant == 1 ? 100UL : 10UL);
        return new(spec, variant == 5 ? new($"other-{seed}") : tenant, cell, new(generation), Digest(), new(9), new(100), new(2), catalog, cardinality);
    }

    internal static GrafanaProjectionRequest Projection(ulong seed, int variant)
    {
        var operation = new ObservabilityOperationId($"operation-{seed}"); var owner = new ObservabilityOwnerId("terrascale"); var tenant = new ObservabilityTenantId($"tenant-{seed}"); var cell = new ObservabilityCellId($"cell-{seed}"); var id = new GrafanaResourceId($"dashboard-{seed}"); var generation = new ObservabilityGeneration(1000 + seed);
        var desired = new DesiredGrafanaResource(id, owner, tenant, cell, generation, new($"release-{seed}"), Digest(), new DashboardSelection(DashboardCatalogEntry.FleetOverview));
        var ownership = variant == 3 ? seed % 2 == 0 ? GrafanaOwnership.Unmanaged : GrafanaOwnership.Conflicting : GrafanaOwnership.ManagedExact;
        var observed = new ObservedGrafanaResource(id, owner, tenant, cell, generation, variant == 1 ? Digest('b') : Digest(), TelemetryProjectionKind.Dashboard, ownership,
            ownership == GrafanaOwnership.ManagedExact ? new(new($"release-{seed}"), new DashboardSelection(DashboardCatalogEntry.FleetOverview)) : null);
        IEnumerable<DesiredGrafanaResource> desiredSet = variant == 2 ? [] : [desired]; IEnumerable<ObservedGrafanaResource> observedSet = variant == 0 ? [] : [observed];
        var inventory = new GrafanaInventoryEvidence(operation, owner, tenant, cell, variant == 4 ? new(generation.Value - 1) : generation, new(9), EvidenceCompleteness.Complete, new(2), observedSet);
        return new(operation, owner, tenant, cell, GrafanaAccessBoundary.Tenant, generation, new(9), generation, new(9), new(2), desiredSet, inventory);
    }

    internal static AlertRoutingRequest Alert(ulong seed, int variant)
    {
        var operation = new ObservabilityOperationId($"operation-{seed}"); var tenant = new ObservabilityTenantId($"tenant-{seed}"); var cell = new ObservabilityCellId($"cell-{seed}"); var signal = new ObservabilitySignalId($"signal-{seed}"); var generation = 1000 + seed; var alertGeneration = variant == 2 ? generation - 1 : variant == 3 ? generation + 1 : generation;
        var alert = new AlertEvent(new($"alert-{seed}"), variant == 4 ? new($"wrong-{seed}") : operation, tenant, cell, signal, new(alertGeneration), Digest(), AlertSeverity.Critical, AlertState.Firing);
        var delivered = variant == 1 ? new[] { new AlertDeliveryKey(alert.AlertId, alert.State) } : [];
        var dedupe = new AlertDedupeEvidence(operation, tenant, cell, variant == 5 ? new($"other-{seed}") : signal, new(generation), Digest(), new(9), new("oncall"), ContactCatalogEntry.GlobalOnCall, alert.Severity, alert.State, EvidenceCompleteness.Complete, new(2), delivered);
        return new(alert, operation, tenant, cell, signal, new(generation), Digest(), new(9), new("oncall"), ContactCatalogEntry.GlobalOnCall, dedupe);
    }

    internal static RegionalHealthRequest Regional(ulong seed, int variant, bool reverse = false)
    {
        var operation = new ObservabilityOperationId($"regional-operation-{seed}"); var cell = new ObservabilityCellId($"regional-cell-{seed}");
        var generation = 2000 + seed; var sequence = 3000 + seed; var retention = 24 + seed % 24; var replicas = 2 + seed % 3; var spoolLimit = 4000 + seed;
        var policies = Enum.GetValues<TelemetrySignalKind>().Select(signal => new RegionalSignalPolicy(signal, TelemetryPersistence.LocalEncryptedSpool,
            new(retention), new(replicas), new(replicas), new(spoolLimit), SpoolOverflowPolicy.DropOldestAndAlert)).ToArray();
        RegionalSignalObservation Observation(TelemetrySignalKind signal) => new(
            signal == TelemetrySignalKind.Metric && variant == 1 ? new($"wrong-operation-{seed}") : operation,
            signal == TelemetrySignalKind.Metric && variant == 2 ? new($"wrong-cell-{seed}") : cell,
            signal,
            new(signal == TelemetrySignalKind.Metric && variant == 11 ? generation + 1 : generation),
            new(signal == TelemetrySignalKind.Metric && variant == 12 ? sequence + 1 : sequence),
            signal == TelemetrySignalKind.Metric && variant == 3 ? Digest('b') : Digest(),
            signal == TelemetrySignalKind.Metric && variant == 4 ? TelemetryPersistence.Memory : TelemetryPersistence.LocalEncryptedSpool,
            new(signal == TelemetrySignalKind.Metric && variant == 5 ? retention - 1 : retention),
            signal == TelemetrySignalKind.Metric && variant == 6 ? replicas - 1 : replicas,
            signal == TelemetrySignalKind.Metric && variant == 7 ? replicas - 1 : replicas,
            signal == TelemetrySignalKind.Metric && variant == 8 ? spoolLimit + 1 : spoolLimit,
            true, SpoolStatus.Healthy);
        var observations = Enum.GetValues<TelemetrySignalKind>().Select(Observation).ToList();
        if (variant == 9) observations.Add(Observation(TelemetrySignalKind.Metric));
        if (variant == 10) observations.Add(new(operationId: new($"conflict-operation-{seed}"), cellId: cell, signal: TelemetrySignalKind.Metric,
            generation: new(generation), sequence: new(sequence), schemaDigest: Digest(), persistence: TelemetryPersistence.Memory,
            retention: new(retention), healthyIngestReplicas: replicas, healthyQueryReplicas: replicas, localSpoolBytes: spoolLimit,
            centralReachable: true, spoolStatus: SpoolStatus.Healthy));
        if (reverse) { Array.Reverse(policies); observations.Reverse(); }
        return new(operation, cell, new(generation), new(sequence), Digest(), new(8), policies, observations);
    }

    internal static ObservabilityDecisionCode RegionalCode(int variant) => variant switch
    {
        4 => ObservabilityDecisionCode.PersistenceExact,
        5 => ObservabilityDecisionCode.RetentionExact,
        6 => ObservabilityDecisionCode.IngestHaSatisfied,
        7 => ObservabilityDecisionCode.QueryHaSatisfied,
        8 => ObservabilityDecisionCode.SpoolWithinPolicy,
        9 or 10 => ObservabilityDecisionCode.EvidenceComplete,
        _ => ObservabilityDecisionCode.ScopeExact,
    };

    internal static string ExpectedRegionalFingerprint(ulong seed, int variant)
    {
        var generation = 2000 + seed; var sequence = 3000 + seed; var retention = 24 + seed % 24; var replicas = 2 + seed % 3; var spool = 4000 + seed;
        var operation = variant == 1 ? $"wrong-operation-{seed}" : $"regional-operation-{seed}"; var cell = variant == 2 ? $"wrong-cell-{seed}" : $"regional-cell-{seed}";
        var metric = $"{operation}:{cell}:{(variant == 11 ? generation + 1 : generation)}:{(variant == 12 ? sequence + 1 : sequence)}:{(variant == 3 ? 'b' : 'a')}:{(variant == 4 ? TelemetryPersistence.Memory : TelemetryPersistence.LocalEncryptedSpool)}:{(variant == 5 ? retention - 1 : retention)}:{(variant == 6 ? replicas - 1 : replicas)}:{(variant == 7 ? replicas - 1 : replicas)}:{(variant == 8 ? spool + 1 : spool)}";
        if (variant == 9) metric += $",regional-operation-{seed}:regional-cell-{seed}:{generation}:{sequence}:a:{TelemetryPersistence.LocalEncryptedSpool}:{retention}:{replicas}:{replicas}:{spool}";
        if (variant == 10) metric += $",conflict-operation-{seed}:regional-cell-{seed}:{generation}:{sequence}:a:{TelemetryPersistence.Memory}:{retention}:{replicas}:{replicas}:{spool}";
        return $"regional-operation-{seed}|regional-cell-{seed}|{generation}|{sequence}|{(variant is 9 or 10 ? 4 : 3)}|{metric}";
    }
}

internal sealed record ObservabilityEntry(string Id, ulong Seed, string Kind, int Variant, string Expected);
internal static class ObservabilityCorpus
{
    private const string Resource = "TerraScale.Orchestrator.ControlPlane.Tests.Properties.ObservabilityReplayCorpus.v1.json"; private const string Digest = "b725a4b56e7b7afc33a2554d2596713ec84989ca64f70dc9d67f3a507dbdf2e8";
    internal static IReadOnlyList<ObservabilityEntry> Load() { using var s = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream(Resource) ?? throw new InvalidDataException(); return Parse(ReadBounded(s), true); }
    internal static byte[] ReadBounded(Stream s) { using var m = new MemoryStream(); var b = new byte[1024]; var total = 0; while (true) { var n = s.Read(b); if (n == 0) break; total += n; if (total > 8192) throw new InvalidDataException(); m.Write(b, 0, n); } return m.ToArray(); }
    internal static IReadOnlyList<ObservabilityEntry> Parse(byte[] bytes, bool enforceDigest) { if (bytes.Length > 8192 || enforceDigest && Convert.ToHexStringLower(SHA256.HashData(bytes)) != Digest) throw new InvalidDataException(); using var d = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4, AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow }); var root = d.RootElement; Exact(root, "schema", "entries"); if (root.GetProperty("schema").GetString() != "terrascale.observability-replay.v1") throw new InvalidDataException(); var result = new List<ObservabilityEntry>(); foreach (var x in root.GetProperty("entries").EnumerateArray()) { if (result.Count == 64) throw new InvalidDataException(); Exact(x, "id", "seed", "kind", "variant", "expected"); result.Add(new(x.GetProperty("id").GetString()!, x.GetProperty("seed").GetUInt64(), x.GetProperty("kind").GetString()!, x.GetProperty("variant").GetInt32(), x.GetProperty("expected").GetString()!)); } if (result.Count == 0 || result.Select(x => x.Id).Distinct().Count() != result.Count || result.Select(x => x.Seed).Distinct().Count() != result.Count || result.Any(x => x.Seed is 0 or > 1_000_000 || !ValidId(x.Id) || !Vocabulary(x))) throw new InvalidDataException(); return result; }
    private static bool Vocabulary(ObservabilityEntry x) => (x.Kind, x.Variant, x.Expected) switch { ("admission", 0, "AdmitTelemetryIntent") or ("admission", 1 or 2 or 4 or 5, "DropTelemetryIntent") or ("admission", 3, "HoldObservabilityIntent") => true, ("projection", 0, "CreateGrafanaResource") or ("projection", 1, "UpdateGrafanaResource") or ("projection", 2, "DeleteGrafanaResource") or ("projection", 3, "ReportGrafanaDrift") or ("projection", 4, "HoldObservabilityIntent") => true, ("alert", 0, "RouteAlertIntent") or ("alert", 1 or 2 or 3 or 4 or 5, "HoldObservabilityIntent") => true,
        ("regional", 0, "AggregateRegionalTelemetryIntent|True|ScopeExact:Passed") or
        ("regional", 1 or 2 or 3, "AggregateRegionalTelemetryIntent|False|ScopeExact:Rejected") or
        ("regional", 4, "AggregateRegionalTelemetryIntent|False|PersistenceExact:Rejected") or
        ("regional", 5, "AggregateRegionalTelemetryIntent|False|RetentionExact:Rejected") or
        ("regional", 6, "AggregateRegionalTelemetryIntent|False|IngestHaSatisfied:Held") or
        ("regional", 7, "AggregateRegionalTelemetryIntent|False|QueryHaSatisfied:Held") or
        ("regional", 8, "AggregateRegionalTelemetryIntent|False|SpoolWithinPolicy:Held") or
        ("regional", 9 or 10, "AggregateRegionalTelemetryIntent|False|EvidenceComplete:Held") or
        ("regional", 11 or 12, "AggregateRegionalTelemetryIntent|False|ScopeExact:Held") => true, _ => false };
    private static bool ValidId(string? x) { if (x is null || x.Length is < 1 or > 64 || x[0] == '-' || x[^1] == '-') return false; var h = false; foreach (var c in x) { var n = c == '-'; if (!(c is >= 'a' and <= 'z' or >= '0' and <= '9') && !n || n && h) return false; h = n; } return true; }
    private static void Exact(JsonElement e, params string[] names) { if (!e.EnumerateObject().Select(p => p.Name).Order().SequenceEqual(names.Order())) throw new InvalidDataException(); }
}
