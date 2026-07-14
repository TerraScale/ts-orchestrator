using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Scheduler.Availability;

namespace TerraScale.Orchestrator.Scheduler.Tests.Properties;

internal enum SchedulerReplayKind{HardConstraint=1,CallerHold=2,AvailabilityFloor=3,ObservationConflict=4,ReserveBoundary=5}
internal sealed record SchedulerReplayEntry(string Identity,ulong Seed,SchedulerReplayKind Kind,string Expected);
internal sealed record SchedulerReplayDocument(string ContentSha256,IReadOnlyList<SchedulerReplayEntry> Entries);

internal static class SchedulerReplayCorpus
{
    internal const int MaximumBytes=8_192;internal const int MaximumEntries=32;
    internal const string ResourceName="TerraScale.Orchestrator.Scheduler.Tests.Properties.ReplayCorpus.scheduler-replay-v1.json";
    internal static SchedulerReplayDocument Load()
    {
        using var stream=typeof(SchedulerReplayCorpus).Assembly.GetManifestResourceStream(ResourceName)??throw new InvalidOperationException("The fixed scheduler replay corpus is missing.");
        return Parse(ReadBounded(stream));
    }
    internal static SchedulerReplayDocument Parse(byte[] bytes)
    {
        if(bytes.Length>MaximumBytes)throw new InvalidOperationException("The scheduler replay corpus exceeds its byte bound.");
        using var document=JsonDocument.Parse(bytes,new(){MaxDepth=4,CommentHandling=JsonCommentHandling.Disallow,AllowTrailingCommas=false});
        var root=document.RootElement;if(root.ValueKind!=JsonValueKind.Object||!ExactProperties(root,"version","entries")||root.GetProperty("version").GetInt32()!=1)
            throw new InvalidOperationException("The scheduler replay corpus envelope is invalid.");
        var entriesElement=root.GetProperty("entries");if(entriesElement.ValueKind!=JsonValueKind.Array)throw new InvalidOperationException("The scheduler replay corpus entries are invalid.");
        var entries=new List<SchedulerReplayEntry>();foreach(var item in entriesElement.EnumerateArray())
        {
            if(entries.Count==MaximumEntries||item.ValueKind!=JsonValueKind.Object||!ExactProperties(item,"identity","seed","kind","expected"))throw new InvalidOperationException("The scheduler replay corpus entry bound or shape is invalid.");
            var identity=item.GetProperty("identity").GetString();var expected=item.GetProperty("expected").GetString();var kindText=item.GetProperty("kind").GetString();
            if(identity is null||identity.Length is<1 or>80||!identity.All(character=>char.IsAsciiLetterOrDigit(character)||character is '-'))throw new InvalidOperationException("A scheduler replay identity is invalid.");
            if(expected is null||expected.Length is<1 or>120||expected.Any(char.IsControl))throw new InvalidOperationException("A scheduler replay expectation is invalid.");
            if(!item.GetProperty("seed").TryGetUInt64(out var seed)||seed==0)throw new InvalidOperationException("A scheduler replay seed is invalid.");
            var kind=kindText switch{"hard-constraint"=>SchedulerReplayKind.HardConstraint,"caller-hold"=>SchedulerReplayKind.CallerHold,
                "availability-floor"=>SchedulerReplayKind.AvailabilityFloor,"observation-conflict"=>SchedulerReplayKind.ObservationConflict,
                "reserve-boundary"=>SchedulerReplayKind.ReserveBoundary,_=>throw new InvalidOperationException("A scheduler replay kind is invalid.")};
            entries.Add(new(identity,seed,kind,expected));
        }
        if(entries.Count==0||entries.Select(entry=>entry.Identity).Distinct(StringComparer.Ordinal).Count()!=entries.Count||entries.Select(entry=>entry.Seed).Distinct().Count()!=entries.Count)
            throw new InvalidOperationException("Scheduler replay identities and seeds must be nonempty and unique.");
        return new(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),Array.AsReadOnly(entries.ToArray()));
    }
    private static byte[] ReadBounded(Stream stream)
    {
        var buffer=new byte[MaximumBytes+1];var total=0;while(total<buffer.Length){var read=stream.Read(buffer,total,buffer.Length-total);if(read==0)break;total+=read;}
        if(total==buffer.Length)throw new InvalidOperationException("The scheduler replay corpus exceeds its byte bound.");return buffer[..total];
    }
    private static bool ExactProperties(JsonElement element,params string[] expected)
    {var properties=element.EnumerateObject().Select(property=>property.Name).ToArray();return properties.Length==expected.Length&&properties.Distinct(StringComparer.Ordinal).Count()==properties.Length&&properties.ToHashSet(StringComparer.Ordinal).SetEquals(expected);}
}

public sealed class SchedulerReplayCorpusTests
{
    private const string ExpectedContentSha256="10f0e0ed8a72189bf318ede88ca5f78cc8347e1a28840ee77ba0587492420073";
    [Test]
    public async Task Embedded_minimal_seed_corpus_is_strict_content_addressed_bounded_and_replays_exactly()
    {
        var corpus=SchedulerReplayCorpus.Load();await Assert.That(corpus.ContentSha256).IsEqualTo(ExpectedContentSha256);
        await Assert.That(corpus.Entries.Count).IsLessThanOrEqualTo(SchedulerReplayCorpus.MaximumEntries);
        foreach(var entry in corpus.Entries){var first=Replay(entry);var second=Replay(entry);await Assert.That(first).IsEqualTo(entry.Expected);await Assert.That(second).IsEqualTo(first);}
    }
    [Test]
    public async Task Corpus_parser_rejects_version_unknown_duplicate_oversized_count_and_seed_mutations()
    {
        var validEntry="{\"identity\":\"id-a\",\"seed\":1,\"kind\":\"caller-hold\",\"expected\":\"rejected:caller-hold\"}";
        var invalid=new[]{"{\"version\":2,\"entries\":[]}","{\"version\":1,\"entries\":[],\"unknown\":1}",
            $"{{\"version\":1,\"entries\":[{validEntry},{validEntry}]}}",$"{{\"version\":1,\"entries\":[{validEntry.Replace("\"seed\":1","\"seed\":0")}]}}",
            $"{{\"version\":1,\"entries\":[{string.Join(',',Enumerable.Repeat(validEntry,33).Select((entry,index)=>entry.Replace("id-a",$"id-{index}").Replace("\"seed\":1",$"\"seed\":{index+1}")))}]}}"};
        foreach(var json in invalid)await Assert.That(Throws(()=>SchedulerReplayCorpus.Parse(Encoding.UTF8.GetBytes(json)))).IsTrue();
        await Assert.That(Throws(()=>SchedulerReplayCorpus.Parse(new byte[SchedulerReplayCorpus.MaximumBytes+1]))).IsTrue();
    }
    private static string Replay(SchedulerReplayEntry entry)=>entry.Kind switch
    {
        SchedulerReplayKind.HardConstraint=>ReplayHardConstraint(entry.Seed),SchedulerReplayKind.CallerHold=>ReplayHold(entry.Seed),
        SchedulerReplayKind.AvailabilityFloor=>ReplayAvailabilityFloor(entry.Seed),SchedulerReplayKind.ObservationConflict=>ReplayConflict(entry.Seed),
        SchedulerReplayKind.ReserveBoundary=>ReplayReserve(entry.Seed),_=>throw new ArgumentOutOfRangeException(nameof(entry))
    };
    private static string ReplayHardConstraint(ulong seed)
    {var property=SchedulerPropertyGenerator.CapacityInvalid(seed);var result=new DeterministicScheduler().Schedule(property.Case.Workload,property.Case.Candidates,property.Case.Policy);return result is Unschedulable?$"rejected:capacity:{property.Check}":"unexpected";}
    private static string ReplayHold(ulong seed)
    {var property=SchedulerPropertyGenerator.Valid(seed);var result=new DeterministicScheduler().Schedule(property.Workload,[SchedulerPropertyGenerator.Vetoed(property.Workload,CandidateVetoCode.StatefulSafetyHold)],property.Policy);return result is Unschedulable?"rejected:caller-hold":"unexpected";}
    private static string ReplayAvailabilityFloor(ulong seed)
    {var property=AvailabilityPropertyGenerator.Maintenance(seed);var count=(ulong)property.Observations.Length;var policy=AvailabilityPropertyGenerator.Policy(count,count,count,1,count,true,ResourceVector.Zero);
        var decision=new AvailabilityPolicyEvaluator().Evaluate(new(policy,property.Maintenance,ObservationCompleteness.Complete,property.Observations));return decision.Admitted?"unexpected":"rejected:availability-floor";}
    private static string ReplayConflict(ulong seed)
    {var property=AvailabilityPropertyGenerator.Maintenance(seed);var conflict=new ReplicaObservation(property.Observations[0].ReplicaId,property.Observations[0].ServiceId,new("conflict"),new("conflict"),ReplicaAvailabilityState.Available);
        var decision=new AvailabilityPolicyEvaluator().Evaluate(new(property.Policy,property.Maintenance,ObservationCompleteness.Complete,property.Observations.Append(conflict)));return decision.Admitted?"unexpected":"rejected:observation-conflict";}
    private static string ReplayReserve(ulong seed)
    {var property=AvailabilityPropertyGenerator.Maintenance(seed);var count=(ulong)property.Observations.Length;var requested=Resources(2);var reserve=Resources(3);var dimension=(int)(seed%8);
        var available=SchedulerPropertyGenerator.WithOneDimension(SchedulerPropertyGenerator.Add(requested,3),dimension,-1);var policy=AvailabilityPropertyGenerator.Policy(count+1,count,count,1,count+1,true,reserve);
        var placement=new PlaceReplicaChange(new($"replica-{count}"),new($"node-{count}"),new($"fd-{count}"),requested,available);
        var decision=new AvailabilityPolicyEvaluator().Evaluate(new(policy,placement,ObservationCompleteness.Complete,property.Observations));var code=(AvailabilityReasonCode)((int)AvailabilityReasonCode.ReserveCpu+dimension);
        return decision.Admitted?"unexpected":$"rejected:reserve-boundary:{code}";}
    private static ResourceVector Resources(long value)=>new(value,value,value,value,value,value,value,value);
    private static bool Throws(Action action){try{action();return false;}catch(Exception exception)when(exception is InvalidOperationException or JsonException){return true;}}
}
