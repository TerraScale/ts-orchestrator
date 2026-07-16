using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Development;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Lab.SmolVm;

internal sealed record SmolVmLabState(
    int SchemaVersion,
    string Profile,
    string RunId,
    long Generation,
    bool Healthy,
    DateTimeOffset ObservedAt,
    string SourceCommit,
    IReadOnlyList<SmolVmMachineInfo> Machines);

internal static class SmolVmLab
{
    private const string Profile = "regions-smol";
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static async Task<int> ExecuteAsync(
        OrchestratorOptions options,
        CancellationToken cancellationToken)
    {
        if (options.LabProfile != OrchestratorLabProfile.RegionsSmol || options.SmolVm is null)
        {
            throw new InvalidOperationException("SmolVmLab requires the regions-smol profile.");
        }
        var configuration = options.SmolVm;
        var topology = CreateTopology(configuration);
        return options.LabCommand switch
        {
            OrchestratorLabCommand.Plan => PrintPlan(topology),
            OrchestratorLabCommand.Status => await PrintStatusAsync(options.StateFile!, cancellationToken),
            OrchestratorLabCommand.Up => await RunAsync(options, configuration, topology, cancellationToken),
            _ => throw new InvalidOperationException($"Unsupported SmolVM lab command {options.LabCommand}.")
        };
    }

    private static SmolVmRegionsTopology CreateTopology(SmolVmLabOptions configuration) =>
        SmolVmRegionsTopology.Create(
            configuration.RunId,
            configuration.BaseArtifact,
            new ArtifactDigest(configuration.BaseArtifactDigest),
            new(
                configuration.CpuCount,
                configuration.MemoryMiB,
                configuration.StorageGiB,
                configuration.OverlayGiB),
            configuration.AllowedEgressCidrs,
            configuration.FirstHostPort);

    private static int PrintPlan(SmolVmRegionsTopology topology)
    {
        Console.WriteLine(JsonSerializer.Serialize(topology, SerializerOptions));
        return 0;
    }

    private static async Task<int> PrintStatusAsync(string stateFile, CancellationToken cancellationToken)
    {
        var state = await ReadStateAsync(stateFile, cancellationToken);
        if (state is null)
        {
            Console.Error.WriteLine("The regions-smol lab has no recorded state.");
            return 1;
        }
        Console.WriteLine(JsonSerializer.Serialize(state, SerializerOptions));
        return state.Healthy ? 0 : 1;
    }

    private static async Task<int> RunAsync(
        OrchestratorOptions options,
        SmolVmLabOptions configuration,
        SmolVmRegionsTopology topology,
        CancellationToken cancellationToken)
    {
        await PreDeploymentEvidence.RequireAsync(
            options.EvidenceFile,
            options.WorkspaceRoot!,
            Profile,
            cancellationToken);
        var installation = await SmolVmInstallationVerifier.VerifyAsync(
            configuration.PinFile,
            configuration.InstallationRoot,
            configuration.RequireInternalProvenance,
            cancellationToken);
        var previous = await ReadStateAsync(options.StateFile!, cancellationToken);
        var generation = (previous?.RunId == configuration.RunId ? previous.Generation : 0) + 1;
        var sourceCommit = await ReadEvidenceCommitAsync(options.EvidenceFile!, cancellationToken);
        var serverData = Path.Combine(options.DataDirectory!, "smolvm", configuration.RunId);
        await using var server = await SmolVmServerSession.StartAsync(
            installation,
            configuration.SocketPath,
            serverData,
            TimeSpan.FromSeconds(45),
            cancellationToken);
        var driver = new SmolVmLabDriver(server.Client);
        try
        {
            while (true)
            {
                var machines = await driver.ConvergeRegionsAsync(topology, cancellationToken);
                await WriteStateAsync(
                    options.StateFile!,
                    new(
                        1,
                        Profile,
                        configuration.RunId,
                        generation,
                        machines.Count == 9 && machines.All(machine => machine.State == "running"),
                        DateTimeOffset.UtcNow,
                        sourceCommit,
                        machines),
                    cancellationToken);
                Console.WriteLine(
                    $"TerraScale regions-smol generation {generation}: {machines.Count(machine => machine.State == "running")}/9 running.");
                await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken);
            }
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            await driver.CleanupAsync(topology, cleanup.Token);
        }
    }

    private static async Task<SmolVmLabState?> ReadStateAsync(
        string stateFile,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(stateFile))
        {
            return null;
        }
        await using var stream = File.OpenRead(stateFile);
        var state = await JsonSerializer.DeserializeAsync<SmolVmLabState>(
            stream,
            SerializerOptions,
            cancellationToken);
        return state is { SchemaVersion: 1, Profile: Profile }
            ? state
            : null;
    }

    private static async Task WriteStateAsync(
        string stateFile,
        SmolVmLabState state,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(stateFile)!);
        var temporary = $"{stateFile}.{Environment.ProcessId}.tmp";
        await using (var stream = new FileStream(
                         temporary,
                         FileMode.Create,
                         FileAccess.Write,
                         FileShare.None,
                         16 * 1024,
                         FileOptions.Asynchronous | FileOptions.WriteThrough))
        {
            await JsonSerializer.SerializeAsync(stream, state, SerializerOptions, cancellationToken);
            await stream.FlushAsync(cancellationToken);
        }
        File.Move(temporary, stateFile, overwrite: true);
    }

    private static async Task<string> ReadEvidenceCommitAsync(
        string evidenceFile,
        CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(evidenceFile);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        return document.RootElement.GetProperty("sourceCommit").GetString()
            ?? throw new InvalidOperationException("Pre-deployment evidence has no source commit.");
    }
}
