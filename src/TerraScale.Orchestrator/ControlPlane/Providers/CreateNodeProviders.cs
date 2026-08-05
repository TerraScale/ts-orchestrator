namespace TerraScale.Orchestrator.ControlPlane.Providers;

public sealed record CreateNodeProviderRequest(
    ProviderOperationContext Context,
    CreateNodeProviderParameters Parameters,
    string TenantId,
    string NodeRequestId,
    CreateNodeHandoffReceipt Receipt);

public sealed record CreateNodeProviderResponse(ProviderResourceId NodeId, ProviderWorkRequestId WorkRequestId);

public interface ICreateNodeProvider
{
    ValueTask<CreateNodeProviderResponse> CreateNodeAsync(CreateNodeProviderRequest request, CancellationToken cancellationToken);
}

/// <summary>Deterministic provider boundary used only by restart/replay tests.</summary>
public sealed class DeterministicCreateNodeProvider(byte[] receiptPublicKey, TimeProvider clock) : ICreateNodeProvider
{
    private readonly byte[] receiptPublicKey = receiptPublicKey?.ToArray() ?? throw new ArgumentNullException(nameof(receiptPublicKey));
    private readonly TimeProvider clock = clock ?? throw new ArgumentNullException(nameof(clock));
    private readonly object gate = new();
    private readonly Dictionary<string, CreateNodeProviderResponse> responses = new(StringComparer.Ordinal);

    public int SideEffectCount { get; private set; }

    public ValueTask<CreateNodeProviderResponse> CreateNodeAsync(CreateNodeProviderRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Validate(request, receiptPublicKey, clock.GetUtcNow());
        lock (gate)
        {
            if (responses.TryGetValue(request.Context.IdempotencyKey.Value, out var existing)) return ValueTask.FromResult(existing);
            var response = new CreateNodeProviderResponse(
                new ProviderResourceId($"fake-node-{request.Context.OperationId.Value}"),
                new ProviderWorkRequestId($"fake-work-{request.Context.OperationId.Value}"));
            responses.Add(request.Context.IdempotencyKey.Value, response);
            SideEffectCount++;
            return ValueTask.FromResult(response);
        }
    }

    internal static void Validate(CreateNodeProviderRequest request, ReadOnlySpan<byte> publicKey, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Context);
        ArgumentNullException.ThrowIfNull(request.Parameters);
        ArgumentNullException.ThrowIfNull(request.Receipt);
        if (request.Context.Action != ProviderAction.CreateNode || request.Context.ResourceKind != ProviderResourceKind.Node ||
            request.Context.ActionParameters != request.Parameters || request.Context.Target is not IdempotentProviderCreate create ||
            !CreateNodeHandoffReceiptVerifier.Verify(request.Receipt, publicKey, request.Context.OperationId.Value,
                request.TenantId, request.NodeRequestId, create.Key.Value, now))
            throw new InvalidOperationException("CreateNode provider request is not an exact, current signed handoff.");
    }
}

/// <summary>Configuration-only OCI boundary. It is disabled unless a separately implemented OCI client is explicitly enabled.</summary>
public sealed record OciCreateNodeProviderOptions(bool Enabled);

public interface IOciCreateNodeClient
{
    ValueTask<CreateNodeProviderResponse> CreateNodeAsync(CreateNodeProviderRequest request, CancellationToken cancellationToken);
}

public sealed class OciCreateNodeProvider(
    OciCreateNodeProviderOptions options,
    IOciCreateNodeClient client,
    byte[] receiptPublicKey,
    TimeProvider clock) : ICreateNodeProvider
{
    private readonly OciCreateNodeProviderOptions options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly IOciCreateNodeClient client = client ?? throw new ArgumentNullException(nameof(client));
    private readonly byte[] receiptPublicKey = receiptPublicKey?.ToArray() ?? throw new ArgumentNullException(nameof(receiptPublicKey));
    private readonly TimeProvider clock = clock ?? throw new ArgumentNullException(nameof(clock));

    public ValueTask<CreateNodeProviderResponse> CreateNodeAsync(CreateNodeProviderRequest request, CancellationToken cancellationToken)
    {
        if (!options.Enabled) throw new InvalidOperationException("OCI CreateNode is disabled until an explicitly configured production adapter is supplied.");
        DeterministicCreateNodeProvider.Validate(request, receiptPublicKey, clock.GetUtcNow());
        return client.CreateNodeAsync(request, cancellationToken);
    }
}
