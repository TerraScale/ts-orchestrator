using System.Text.Json;
using System.Text.Json.Nodes;

namespace TsOrch.Cli;

internal sealed record class NetBirdInitOptions(string? Api, string? PatFile, string? OwnerPasswordFile, string? ExportDirectory);

internal sealed class NetBirdInitializer(CommandEnvironment environment)
{
    public async Task<int> RunAsync(FleetConfig fleet, NetBirdInitOptions options, CancellationToken cancellationToken)
    {
        if (fleet.NetBird is not { } config)
        {
            return environment.Usage("Fleet configuration has no netbird section.");
        }

        if (NetBirdApi.ParseUrl(options.Api ?? config.ManagementUrl) is not { } url)
        {
            return environment.Usage("NetBird API needs an HTTPS origin or a loopback HTTP origin.");
        }

        if (fleet.Regions.Count == 0)
        {
            return environment.Usage("NetBird initialization requires at least one fleet region.");
        }

        if (options.ExportDirectory is not { } requestedDirectory)
        {
            return await InitializeAsync(fleet, config, options, url, null, cancellationToken);
        }

        var directory = NetBirdCredentials.PrepareDirectory(requestedDirectory);
        return directory switch
        {
            NetBirdExportDirectory output => await InitializeAsync(fleet, config, options, url, output, cancellationToken),
            NetBirdExportDirectoryUnavailable failure => environment.Fail(failure.Diagnostic),
        };
    }

    private async Task<int> InitializeAsync(
        FleetConfig fleet, NetBirdConfig config, NetBirdInitOptions options, Uri url, NetBirdExportDirectory? output, CancellationToken cancellationToken)
    {
        using var api = new NetBirdApi(url, environment.TimeProvider);
        var instance = await api.GetInstanceAsync(cancellationToken);
        var token = instance switch
        {
            NetBirdInstance { SetupRequired: true } => await ClaimOwnerAsync(api, fleet.Oci.Vault, config, options, output, cancellationToken),
            NetBirdInstance => await NetBirdCredentials.ReadAsync(options.PatFile, fleet.Oci.Vault, config.AdminPatSecret, environment.TimeProvider, cancellationToken),
            NetBirdApiProblem problem => new NetBirdCredentialUnavailable(NetBirdApi.Describe(problem)),
        };
        return token switch
        {
            NetBirdCredential credential when NetBirdCredentials.IsToken(credential.Value)
                => await ReconcileAsync(api, credential, fleet, config, output, cancellationToken),
            NetBirdCredential => environment.Usage("The NetBird admin PAT has an invalid format."),
            NetBirdCredentialUnavailable failure => environment.Fail(failure.Diagnostic),
        };
    }

    private async Task<NetBirdCredentialRead> ClaimOwnerAsync(
        NetBirdApi api, VaultConfig vault, NetBirdConfig config, NetBirdInitOptions options, NetBirdExportDirectory? output, CancellationToken cancellationToken)
    {
        var password = await NetBirdCredentials.ReadAsync(
            options.OwnerPasswordFile, vault, config.OwnerPasswordSecret, environment.TimeProvider, cancellationToken);
        return password switch
        {
            NetBirdCredential credential => await SetUpAsync(api, config, credential, output, cancellationToken),
            NetBirdCredentialUnavailable unavailable => unavailable,
        };
    }

    private async Task<NetBirdCredentialRead> SetUpAsync(
        NetBirdApi api, NetBirdConfig config, NetBirdCredential password, NetBirdExportDirectory? output, CancellationToken cancellationToken)
    {
        var outcome = await api.SendAsync(HttpMethod.Post, "/api/setup", new JsonObject
        {
            ["email"] = config.OwnerEmail,
            ["name"] = "TerraScale Owner",
            ["password"] = password.Value,
            ["create_pat"] = true,
            ["pat_expire_in"] = 90,
        }, cancellationToken);
        return outcome switch
        {
            JsonElement document when NetBirdJson.Text(document, "personal_access_token") is { } token && NetBirdCredentials.IsToken(token)
                => await SaveOwnerPatAsync(new NetBirdCredential(token), config.AdminPatSecret, output, cancellationToken),
            JsonElement => new NetBirdCredentialUnavailable(CliDiagnostic.Unavailable("NetBird setup returned no usable admin PAT. Create an admin PAT and run init with --pat-file.")),
            NetBirdApiProblem problem => new NetBirdCredentialUnavailable(NetBirdApi.Describe(problem)),
        };
    }

    private async Task<NetBirdCredentialRead> SaveOwnerPatAsync(
        NetBirdCredential token, string secretName, NetBirdExportDirectory? output, CancellationToken cancellationToken)
    {
        var failure = await ExportAsync(output, "admin.pat", token, secretName, cancellationToken);
        return failure is null ? token : new NetBirdCredentialUnavailable(failure);
    }

    private async Task<int> ReconcileAsync(
        NetBirdApi api, NetBirdCredential token, FleetConfig fleet, NetBirdConfig config, NetBirdExportDirectory? output, CancellationToken cancellationToken)
    {
        api.Token = token;
        var management = new NetBirdManagement(api, environment.TimeProvider);
        var account = await management.GetAccountAsync(cancellationToken);
        var failure = account switch
        {
            NetBirdAccount current => await management.SetAccountAsync(current, config, cancellationToken),
            NetBirdApiProblem problem => problem,
        };
        if (failure is not null)
        {
            return environment.Fail(NetBirdApi.Describe(failure));
        }

        string[] regionalGroups = [.. fleet.Regions.Select(static region => NetBirdManagement.ServerGroup(region.Label)).Distinct(StringComparer.Ordinal)];
        var groups = await management.EnsureGroupsAsync([NetBirdManagement.Operators, NetBirdManagement.OpsAutomation, .. regionalGroups], cancellationToken);
        return groups switch
        {
            IReadOnlyList<NetBirdGroup> reconciled => await ReconcileAccessAsync(management, config, reconciled, regionalGroups, output, cancellationToken),
            NetBirdApiProblem problem => environment.Fail(NetBirdApi.Describe(problem)),
        };
    }

    private async Task<int> ReconcileAccessAsync(
        NetBirdManagement management,
        NetBirdConfig config,
        IReadOnlyList<NetBirdGroup> groups,
        IReadOnlyList<string> regionalGroups,
        NetBirdExportDirectory? output,
        CancellationToken cancellationToken)
    {
        var operators = groups.First(static group => group.Name == NetBirdManagement.Operators).Id;
        var automation = groups.First(static group => group.Name == NetBirdManagement.OpsAutomation).Id;
        string[] servers = [.. regionalGroups.Select(name => groups.First(group => group.Name == name).Id)];
        var problem = await management.EnsurePoliciesAsync([operators, automation], servers, cancellationToken);
        if (problem is not null)
        {
            return environment.Fail(NetBirdApi.Describe(problem));
        }

        var outcome = await management.GetSetupKeysAsync(cancellationToken);
        return outcome switch
        {
            IReadOnlyList<NetBirdSetupKey> keys => await ReconcileKeysAsync(management, config, keys, servers, operators, output, cancellationToken),
            NetBirdApiProblem failure => environment.Fail(NetBirdApi.Describe(failure)),
        };
    }

    private async Task<int> ReconcileKeysAsync(
        NetBirdManagement management,
        NetBirdConfig config,
        IReadOnlyList<NetBirdSetupKey> keys,
        IReadOnlyList<string> servers,
        string operators,
        NetBirdExportDirectory? output,
        CancellationToken cancellationToken)
    {
        SetupKeyTarget[] targets =
        [
            new(NetBirdManagement.Servers, servers, config.SetupKeySecret),
            new(NetBirdManagement.Operators, [operators], config.OperatorsSetupKeySecret),
        ];
        foreach (var target in targets)
        {
            var outcome = await management.EnsureSetupKeyAsync(keys, target.Name, target.AutoGroups, cancellationToken);
            var problem = outcome switch
            {
                NetBirdSetupKeyUnchanged => null,
                NetBirdSetupKeyCreated key => await ExportSetupKeyAsync(management, output, target, key, cancellationToken),
                NetBirdApiProblem failure => NetBirdApi.Describe(failure),
            };
            if (problem is not null)
            {
                return environment.Fail(problem);
            }
        }

        environment.Out.WriteLine("NetBird account settings, groups, policies, and setup keys are ready.");
        return ExitCodes.Ok;
    }

    private async Task<CliDiagnostic?> ExportSetupKeyAsync(
        NetBirdManagement management, NetBirdExportDirectory? output, SetupKeyTarget target, NetBirdSetupKeyCreated key, CancellationToken cancellationToken)
    {
        CliDiagnostic? failure;
        NetBirdApiProblem? revokeFailure = null;
        var published = false;
        try
        {
            failure = await ExportAsync(output, $"{target.Name}.setup-key", key.Value, target.VaultSecret, cancellationToken);
            published = failure is null;
        }
        finally
        {
            if (published is false)
            {
                revokeFailure = await management.RevokeSetupKeyAsync(key.Id, target.AutoGroups, CancellationToken.None);
            }
        }

        return failure is not null && revokeFailure is not null
            ? CliDiagnostic.Unavailable($"{failure.Message} {NetBirdApi.Describe(revokeFailure).Message}")
            : failure;
    }

    private async Task<CliDiagnostic?> ExportAsync(
        NetBirdExportDirectory? output, string fileName, NetBirdCredential credential, string vaultSecret, CancellationToken cancellationToken)
    {
        if (output is null)
        {
            environment.Error.WriteLine($"NetBird issued a credential for Vault secret '{vaultSecret}'. Credentials can only be exported when issued. Pass --write-setup-keys-dir to export the next credential.");
            return null;
        }

        var path = Path.Combine(output.Path, fileName);
        var outcome = await CliFiles.WritePrivateTextAsync(path, credential.Value, cancellationToken);
        var failure = outcome switch
        {
            PrivateFileWritten => null,
            PrivateFileTargetInvalid invalid => CliDiagnostic.Usage(invalid.Message),
            PrivateFileWriteDenied denied => CliDiagnostic.Permission($"Could not write '{denied.Path}'."),
            PrivateFileWriteInterrupted interrupted => CliDiagnostic.Unavailable($"Could not write '{interrupted.Path}'."),
        };
        if (failure is null)
        {
            environment.Out.WriteLine($"{path} (upload to OCI Vault secret '{vaultSecret}')");
        }

        return failure;
    }

    private sealed record class SetupKeyTarget(string Name, IReadOnlyList<string> AutoGroups, string VaultSecret);
}
