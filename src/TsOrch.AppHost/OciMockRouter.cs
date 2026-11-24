using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace TsOrch.AppHost;

internal sealed partial class OciMockRouter(OciMockState state, OciMockIdentity identity, OciMockFederation federation, ILogger<OciMockRouter> logger)
{
    private const string ImdsBearer = "Bearer Oracle";
    private static readonly AppHostJsonContext Json = AppHostJsonContext.Default;
    private static readonly string[] SecretStages = ["CURRENT", "LATEST"];
    private static readonly string[] InstanceActions = ["STOP", "START", "SOFTRESET", "RESET", "SOFTSTOP", "SENDDIAGNOSTICINTERRUPT"];

    public Task HandleAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var request = context.Request;
        var segments = request.Path.Value is { } path ? path.Split('/', StringSplitOptions.RemoveEmptyEntries) : [];
        context.Response.Headers["opc-request-id"] = Convert.ToHexStringLower(Guid.NewGuid().ToByteArray());
        return (request.Method, segments) switch
        {
            ("GET", ["healthz"]) => WriteJsonAsync(context, StatusCodes.Status200OK, new HealthDocument(true, "oci-mock"), Json.HealthDocument),
            ("GET", ["_mock", "state"]) => WriteJsonAsync(context, StatusCodes.Status200OK, state.Snapshot(), Json.MockStateDocument),
            ("POST", ["_mock", "secrets", var name, "bump"]) => BumpSecretAsync(context, name),
            ("GET", ["opc", "v2", "instance"]) => ImdsJsonAsync(context, identity.Instance, Json.ImdsInstanceDocument),
            ("GET", ["opc", "v2", "vnics"]) => ImdsJsonAsync(context, identity.Vnics, Json.IReadOnlyListImdsVnicDocument),
            ("GET", ["opc", "v2", "identity", "cert.pem"]) => ImdsTextAsync(context, identity.LeafCertificatePem),
            ("GET", ["opc", "v2", "identity", "key.pem"]) => ImdsTextAsync(context, identity.LeafPrivateKeyPem),
            ("GET", ["opc", "v2", "identity", "intermediate.pem"]) => ImdsTextAsync(context, identity.IntermediateCertificatePem),
            ("POST", ["v1", "x509"]) => FederateAsync(context, context.RequestAborted),
            ("POST", ["20190301", "secretbundles", "actions", "getByName"]) => GetSecretBundleAsync(context),
            ("GET", ["20160918", "instancePools", var poolId]) => GetPoolAsync(context, poolId),
            ("PUT", ["20160918", "instancePools", var poolId]) => UpdatePoolAsync(context, poolId),
            ("POST", ["20160918", "instancePools", var poolId, "actions", "detachInstance"]) => DetachInstanceAsync(context, poolId),
            ("DELETE", ["20160918", "instances", var instanceId]) => TerminateInstanceAsync(context, instanceId),
            ("POST", ["20160918", "instances", var instanceId]) => InstanceActionAsync(context, instanceId),
            ("PUT", ["20160918", "volumes", var volumeId]) => UpdateVolumeAsync(context, volumeId),
            _ => ErrorAsync(context, StatusCodes.Status404NotFound, "NotAuthorizedOrNotFound", $"oci-mock has no route for {request.Method} {request.Path}"),
        };
    }

    private Task BumpSecretAsync(HttpContext context, string name)
    {
        var secret = state.BumpSecret(name);
        LogSecretBumped(logger, name, secret.Version);
        return WriteJsonAsync(context, StatusCodes.Status200OK, new SecretVersionDocument(name, secret.Version), Json.SecretVersionDocument);
    }

    private static Task ImdsJsonAsync<T>(HttpContext context, T value, JsonTypeInfo<T> typeInfo) =>
        Authorized(context.Request, ImdsBearer)
            ? WriteJsonAsync(context, StatusCodes.Status200OK, value, typeInfo)
            : ErrorAsync(context, StatusCodes.Status401Unauthorized, "NotAuthenticated", "IMDS v2 requires 'Authorization: Bearer Oracle'.");

    private static async Task ImdsTextAsync(HttpContext context, string pem)
    {
        if (!Authorized(context.Request, ImdsBearer))
        {
            await ErrorAsync(context, StatusCodes.Status401Unauthorized, "NotAuthenticated", "IMDS v2 requires 'Authorization: Bearer Oracle'.");
            return;
        }

        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "text/plain; charset=utf-8";
        await context.Response.WriteAsync(pem, context.RequestAborted);
    }

    private async Task FederateAsync(HttpContext context, CancellationToken cancellationToken)
    {
        try
        {
            using var body = new MemoryStream();
            await context.Request.Body.CopyToAsync(body, cancellationToken);
            var bytes = body.ToArray();
            if (JsonSerializer.Deserialize(bytes, Json.MockFederationRequest) is not { } document)
            {
                await ErrorAsync(context, StatusCodes.Status400BadRequest, "InvalidParameter", "A federation document is required.");
                return;
            }

            if (federation.Issue(context.Request, document, bytes) is not { } token)
            {
                await UnsignedAsync(context);
                return;
            }

            await WriteJsonAsync(context, StatusCodes.Status200OK, new MockFederationResponse(token), Json.MockFederationResponse);
        }
        catch (JsonException exception)
        {
            await ErrorAsync(context, StatusCodes.Status400BadRequest, "InvalidParameter", exception.Message);
        }
    }

    private Task GetSecretBundleAsync(HttpContext context)
    {
        var request = context.Request;
        if (!federation.VerifyVault(request))
        {
            return ErrorAsync(context, StatusCodes.Status401Unauthorized, "NotAuthenticated", "oci-mock Vault requires a valid instance-principal signature.");
        }

        var secretName = request.Query["secretName"].ToString();
        var vaultId = request.Query["vaultId"].ToString();
        if (secretName.Length == 0 || vaultId.Length == 0)
        {
            return ErrorAsync(context, StatusCodes.Status400BadRequest, "MissingParameter", "secretName and vaultId are required.");
        }

        if (state.FindSecret(secretName) is not { } secret)
        {
            return ErrorAsync(context, StatusCodes.Status404NotFound, "NotAuthorizedOrNotFound", $"Secret '{secretName}' does not exist in vault '{vaultId}'.");
        }

        var bundle = new SecretBundleDocument(
            secret.SecretId,
            secret.Version,
            SecretStages,
            secret.CreatedAt.ToString("O", CultureInfo.InvariantCulture),
            new SecretBundleContentDocument("BASE64", Convert.ToBase64String(Encoding.UTF8.GetBytes(secret.Value))));
        return WriteJsonAsync(context, StatusCodes.Status200OK, bundle, Json.SecretBundleDocument);
    }

    private Task GetPoolAsync(HttpContext context, string poolId) =>
        Signed(context.Request)
            ? WriteJsonAsync(context, StatusCodes.Status200OK, state.GetPool(poolId), Json.InstancePoolDocument)
            : UnsignedAsync(context);

    private async Task UpdatePoolAsync(HttpContext context, string poolId)
    {
        if (!Signed(context.Request))
        {
            await UnsignedAsync(context);
            return;
        }

        await WithJsonBodyAsync(context, Json.UpdateInstancePoolDocument, update => update.Size >= 0
            ? WritePoolAsync(context, state.UpdatePool(context.Request.Path, poolId, update.Size))
            : ErrorAsync(context, StatusCodes.Status400BadRequest, "InvalidParameter", $"size must be non-negative, got {update.Size.ToString(CultureInfo.InvariantCulture)}."), context.RequestAborted);
    }

    private async Task DetachInstanceAsync(HttpContext context, string poolId)
    {
        if (!Signed(context.Request))
        {
            await UnsignedAsync(context);
            return;
        }

        await WithJsonBodyAsync(context, Json.DetachInstanceDocument, detach => detach.InstanceId.Length > 0
            ? WritePoolAsync(context, state.DetachInstance(context.Request.Path, poolId, detach))
            : ErrorAsync(context, StatusCodes.Status400BadRequest, "InvalidParameter", "instanceId is required."), context.RequestAborted);
    }

    private Task WritePoolAsync(HttpContext context, InstancePoolDocument pool)
    {
        LogPool(logger, pool.Id, pool.Size);
        return WriteJsonAsync(context, StatusCodes.Status200OK, pool, Json.InstancePoolDocument);
    }

    private Task TerminateInstanceAsync(HttpContext context, string instanceId)
    {
        if (!Signed(context.Request))
        {
            return UnsignedAsync(context);
        }

        var preserveBootVolume = context.Request.Query["preserveBootVolume"].ToString();
        state.TerminateInstance(context.Request.Path, instanceId, preserveBootVolume.Length == 0 ? "false" : preserveBootVolume);
        LogTerminated(logger, instanceId);
        context.Response.StatusCode = StatusCodes.Status204NoContent;
        return Task.CompletedTask;
    }

    private Task InstanceActionAsync(HttpContext context, string instanceId)
    {
        if (!Signed(context.Request))
        {
            return UnsignedAsync(context);
        }

        var action = context.Request.Query["action"].ToString();
        if (!InstanceActions.Contains(action, StringComparer.Ordinal))
        {
            return ErrorAsync(context, StatusCodes.Status400BadRequest, "InvalidParameter", $"Unsupported instance action '{action}'.");
        }

        var instance = state.InstanceAction(context.Request.Path, instanceId, action);
        LogInstanceAction(logger, instanceId, action);
        return WriteJsonAsync(context, StatusCodes.Status200OK, instance, Json.InstanceDocument);
    }

    private async Task UpdateVolumeAsync(HttpContext context, string volumeId)
    {
        if (!Signed(context.Request))
        {
            await UnsignedAsync(context);
            return;
        }

        await WithJsonBodyAsync(context, Json.UpdateVolumeDocument, update => update.SizeInGBs > 0
            ? ResizeVolumeAsync(context, volumeId, update.SizeInGBs)
            : ErrorAsync(context, StatusCodes.Status400BadRequest, "InvalidParameter", $"sizeInGBs must be positive, got {update.SizeInGBs.ToString(CultureInfo.InvariantCulture)}."), context.RequestAborted);
    }

    private Task ResizeVolumeAsync(HttpContext context, string volumeId, long sizeInGBs) =>
        state.UpdateVolume(context.Request.Path, volumeId, sizeInGBs) switch
        {
            VolumeDocument volume => WriteVolumeAsync(context, volume),
            MockVolumeShrinkRejected rejected => ErrorAsync(context, StatusCodes.Status400BadRequest, "InvalidParameter", rejected.Message),
        };

    private Task WriteVolumeAsync(HttpContext context, VolumeDocument volume)
    {
        LogVolume(logger, volume.Id, volume.SizeInGBs);
        return WriteJsonAsync(context, StatusCodes.Status200OK, volume, Json.VolumeDocument);
    }

    private static Task UnsignedAsync(HttpContext context) =>
        ErrorAsync(context, StatusCodes.Status401Unauthorized, "NotAuthenticated", "OCI REST calls require an 'Authorization: Signature version=\"1\",keyId=...' header.");

    private static bool Authorized(HttpRequest request, string expected) =>
        string.Equals(request.Headers.Authorization.ToString(), expected, StringComparison.Ordinal);

    private static bool Signed(HttpRequest request) =>
        request.Headers.Authorization.ToString() is var header
        && header.StartsWith("Signature ", StringComparison.Ordinal)
        && header.Contains("keyId=\"", StringComparison.Ordinal)
        && header.Contains("signature=\"", StringComparison.Ordinal);

    private static async Task WithJsonBodyAsync<T>(
        HttpContext context,
        JsonTypeInfo<T> typeInfo,
        Func<T, Task> handle,
        CancellationToken cancellationToken) where T : class
    {
        T? document;
        try
        {
            document = await JsonSerializer.DeserializeAsync(context.Request.Body, typeInfo, cancellationToken);
        }
        catch (JsonException exception)
        {
            await ErrorAsync(context, StatusCodes.Status400BadRequest, "InvalidParameter", exception.Message);
            return;
        }

        if (document is null)
        {
            await ErrorAsync(context, StatusCodes.Status400BadRequest, "InvalidParameter", "Request body must be a JSON object.");
            return;
        }

        await handle(document);
    }

    private static async Task WriteJsonAsync<T>(HttpContext context, int statusCode, T value, JsonTypeInfo<T> typeInfo)
    {
        context.Response.StatusCode = statusCode;
        await context.Response.WriteAsJsonAsync(value, typeInfo, contentType: "application/json", context.RequestAborted);
    }

    private static Task ErrorAsync(HttpContext context, int statusCode, string code, string message) =>
        WriteJsonAsync(context, statusCode, new OciErrorDocument(code, message), Json.OciErrorDocument);

    [LoggerMessage(Level = LogLevel.Information, Message = "oci-mock instance pool {PoolId} size is now {Size}")]
    private static partial void LogPool(ILogger logger, string poolId, int size);

    [LoggerMessage(Level = LogLevel.Information, Message = "oci-mock terminated instance {InstanceId}")]
    private static partial void LogTerminated(ILogger logger, string instanceId);

    [LoggerMessage(Level = LogLevel.Information, Message = "oci-mock instance {InstanceId} action {Action}")]
    private static partial void LogInstanceAction(ILogger logger, string instanceId, string action);

    [LoggerMessage(Level = LogLevel.Information, Message = "oci-mock volume {VolumeId} resized to {SizeInGBs} GB")]
    private static partial void LogVolume(ILogger logger, string volumeId, long sizeInGBs);

    [LoggerMessage(Level = LogLevel.Information, Message = "oci-mock secret {SecretName} bumped to version {Version}")]
    private static partial void LogSecretBumped(ILogger logger, string secretName, long version);
}
