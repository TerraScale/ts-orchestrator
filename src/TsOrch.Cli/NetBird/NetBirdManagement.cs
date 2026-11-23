using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace TsOrch.Cli;

internal sealed record class NetBirdAccount(string Id, JsonElement Settings, JsonElement Onboarding)
{
    public string? DnsDomain => NetBirdJson.Text(Settings, "dns_domain");
}

internal sealed record class NetBirdGroup(string Name, string Id);

internal sealed record class NetBirdSetupKey(
    string Id, string Name, string Type, bool Valid, bool Revoked, DateTimeOffset Expires, IReadOnlyList<string> AutoGroups)
{
    public bool IsUsable(DateTimeOffset cutoff) => Type == "reusable" && Valid && Revoked is false && Expires > cutoff;
}

internal sealed record class NetBirdSetupKeyUnchanged;

internal sealed record class NetBirdSetupKeyCreated(string Id, NetBirdCredential Value);

internal readonly union NetBirdAccountLookup(NetBirdAccount, NetBirdApiProblem);

internal readonly union NetBirdGroupsLookup(IReadOnlyList<NetBirdGroup>, NetBirdApiProblem);

internal readonly union NetBirdSetupKeysLookup(IReadOnlyList<NetBirdSetupKey>, NetBirdApiProblem);

internal readonly union NetBirdSetupKeyReconciliation(NetBirdSetupKeyUnchanged, NetBirdSetupKeyCreated, NetBirdApiProblem);

internal sealed class NetBirdManagement(NetBirdApi api, TimeProvider timeProvider)
{
    public const string Operators = "operators";
    public const string OpsAutomation = "ops-automation";
    public const string Servers = "servers";

    private const string AccountsPath = "/api/accounts";
    private const string GroupsPath = "/api/groups";
    private const string PoliciesPath = "/api/policies";
    private const string SetupKeysPath = "/api/setup-keys";
    private const int SetupKeyLifetimeSeconds = 90 * 24 * 60 * 60;

    public static string ServerGroup(string region) => $"{region}-servers";

    public async Task<NetBirdAccountLookup> GetAccountAsync(CancellationToken cancellationToken)
    {
        var outcome = await api.SendAsync(HttpMethod.Get, AccountsPath, null, cancellationToken);
        return outcome switch
        {
            JsonElement response when NetBirdJson.Items(response) is [var account]
                && NetBirdJson.Text(account, "id") is { } id
                && NetBirdJson.Property(account, "settings") is { ValueKind: JsonValueKind.Object } settings
                => new NetBirdAccount(id, settings, NetBirdJson.Property(account, "onboarding")),
            JsonElement => new NetBirdResponseInvalid("GET /api/accounts"),
            NetBirdApiProblem problem => problem,
        };
    }

    public async Task<NetBirdApiProblem?> SetAccountAsync(NetBirdAccount account, NetBirdConfig config, CancellationToken cancellationToken)
    {
        var currentRange = NetBirdJson.Text(account.Settings, "network_range");
        var changeRange = string.IsNullOrWhiteSpace(config.NetworkRange) is false
            && currentRange is not null && string.Equals(currentRange, config.NetworkRange, StringComparison.Ordinal) is false;
        if (account.DnsDomain == config.DnsDomain && changeRange is false)
        {
            return null;
        }

        var settings = JsonObject.Create(account.Settings) ?? throw new InvalidOperationException("NetBird account settings must be an object.");
        settings["dns_domain"] = config.DnsDomain;
        if (changeRange)
        {
            settings["network_range"] = config.NetworkRange;
        }

        var body = new JsonObject { ["settings"] = settings };
        if (account.Onboarding.ValueKind == JsonValueKind.Object)
        {
            body["onboarding"] = JsonObject.Create(account.Onboarding);
        }

        return await ApplyAsync(HttpMethod.Put, ById(AccountsPath, account.Id), body, cancellationToken);
    }

    public async Task<NetBirdGroupsLookup> GetGroupsAsync(CancellationToken cancellationToken)
    {
        var outcome = await api.SendAsync(HttpMethod.Get, GroupsPath, null, cancellationToken);
        return outcome switch
        {
            JsonElement { ValueKind: JsonValueKind.Array } response => ParseGroups(response),
            JsonElement => new NetBirdResponseInvalid("GET /api/groups"),
            NetBirdApiProblem problem => problem,
        };
    }

    public async Task<NetBirdGroupsLookup> EnsureGroupsAsync(IReadOnlyList<string> names, CancellationToken cancellationToken)
    {
        var outcome = await GetGroupsAsync(cancellationToken);
        return outcome switch
        {
            IReadOnlyList<NetBirdGroup> existing => await CreateMissingGroupsAsync(existing, names, cancellationToken),
            NetBirdApiProblem problem => problem,
        };
    }

    private async Task<NetBirdGroupsLookup> CreateMissingGroupsAsync(
        IReadOnlyList<NetBirdGroup> existing, IReadOnlyList<string> names, CancellationToken cancellationToken)
    {
        List<NetBirdGroup> groups = [.. existing];
        foreach (var name in names.Distinct(StringComparer.Ordinal))
        {
            if (groups.Any(group => group.Name == name))
            {
                continue;
            }

            var outcome = await api.SendAsync(HttpMethod.Post, GroupsPath, new JsonObject { ["name"] = name }, cancellationToken);
            var problem = outcome switch
            {
                JsonElement document when ParseGroup(document) is { } group && group.Name == name => AddGroup(groups, group),
                JsonElement => new NetBirdResponseInvalid("POST /api/groups"),
                NetBirdApiProblem failure => failure,
            };
            if (problem is not null)
            {
                return problem;
            }
        }

        return (IReadOnlyList<NetBirdGroup>)groups;
    }

    private static NetBirdApiProblem? AddGroup(List<NetBirdGroup> groups, NetBirdGroup group)
    {
        groups.Add(group);
        return null;
    }

    public async Task<NetBirdApiProblem?> EnsurePoliciesAsync(
        IReadOnlyList<string> operatorIds, IReadOnlyList<string> serverIds, CancellationToken cancellationToken)
    {
        var outcome = await api.SendAsync(HttpMethod.Get, PoliciesPath, null, cancellationToken);
        return outcome switch
        {
            JsonElement { ValueKind: JsonValueKind.Array } policies
                => await ReconcilePoliciesAsync(NetBirdJson.Items(policies), operatorIds, serverIds, cancellationToken),
            JsonElement => new NetBirdResponseInvalid("GET /api/policies"),
            NetBirdApiProblem problem => problem,
        };
    }

    private async Task<NetBirdApiProblem?> ReconcilePoliciesAsync(
        IReadOnlyList<JsonElement> policies, IReadOnlyList<string> operatorIds, IReadOnlyList<string> serverIds, CancellationToken cancellationToken)
    {
        var ssh = new AccessPolicy("operators-ssh-to-servers", "tcp", false, operatorIds, serverIds, ["22"]);
        var mesh = new AccessPolicy("servers-mesh", "all", true, serverIds, serverIds, []);
        foreach (var policy in new[] { ssh, mesh })
        {
            var existing = policies.FirstOrDefault(document => NetBirdJson.Text(document, "name") == policy.Name);
            if (policy.Matches(existing))
            {
                continue;
            }

            var id = NetBirdJson.Text(existing, "id");
            if (existing.ValueKind is not JsonValueKind.Undefined && id is null)
            {
                return new NetBirdResponseInvalid("GET /api/policies");
            }

            var ruleId = NetBirdJson.Items(existing, "rules") is [var rule, ..] ? NetBirdJson.Text(rule, "id") : null;
            var failure = id is null
                ? await ApplyAsync(HttpMethod.Post, PoliciesPath, policy.ToJson(ruleId), cancellationToken)
                : await ApplyAsync(HttpMethod.Put, ById(PoliciesPath, id), policy.ToJson(ruleId), cancellationToken);
            if (failure is not null)
            {
                return failure;
            }
        }

        foreach (var policy in policies.Where(static document => NetBirdJson.Text(document, "name") == "Default"))
        {
            if (NetBirdJson.Text(policy, "id") is not { } id)
            {
                return new NetBirdResponseInvalid("GET /api/policies");
            }

            var failure = await ApplyAsync(HttpMethod.Delete, ById(PoliciesPath, id), null, cancellationToken);
            if (failure is not (null or NetBirdRequestRejected { Status: HttpStatusCode.NotFound }))
            {
                return failure;
            }
        }

        return null;
    }

    public async Task<NetBirdSetupKeysLookup> GetSetupKeysAsync(CancellationToken cancellationToken)
    {
        var outcome = await api.SendAsync(HttpMethod.Get, SetupKeysPath, null, cancellationToken);
        return outcome switch
        {
            JsonElement { ValueKind: JsonValueKind.Array } response => ParseSetupKeys(response),
            JsonElement => new NetBirdResponseInvalid("GET /api/setup-keys"),
            NetBirdApiProblem problem => problem,
        };
    }

    public async Task<NetBirdSetupKeyReconciliation> EnsureSetupKeyAsync(
        IReadOnlyList<NetBirdSetupKey> keys, string name, IReadOnlyList<string> autoGroups, CancellationToken cancellationToken)
    {
        var cutoff = timeProvider.GetUtcNow().AddDays(30);
        var existing = keys.Where(key => key.Name == name && key.IsUsable(cutoff))
            .OrderByDescending(static key => key.Expires)
            .FirstOrDefault();
        if (existing is not null)
        {
            if (SameSet(existing.AutoGroups, autoGroups))
            {
                return new NetBirdSetupKeyUnchanged();
            }

            var problem = await ApplyAsync(HttpMethod.Put, ById(SetupKeysPath, existing.Id), SetupKeyUpdate(autoGroups, revoked: false), cancellationToken);
            return problem is null ? new NetBirdSetupKeyUnchanged() : problem;
        }

        var outcome = await api.SendAsync(HttpMethod.Post, SetupKeysPath, new JsonObject
        {
            ["name"] = name,
            ["type"] = "reusable",
            ["expires_in"] = SetupKeyLifetimeSeconds,
            ["auto_groups"] = NetBirdJson.Strings(autoGroups),
            ["usage_limit"] = 0,
            ["ephemeral"] = false,
        }, cancellationToken);
        return outcome switch
        {
            JsonElement response when NetBirdJson.Text(response, "id") is { } id
                && NetBirdJson.Text(response, "key") is { } key && NetBirdCredentials.IsToken(key)
                => new NetBirdSetupKeyCreated(id, new NetBirdCredential(key)),
            JsonElement => new NetBirdResponseInvalid("POST /api/setup-keys"),
            NetBirdApiProblem problem => problem,
        };
    }

    public Task<NetBirdApiProblem?> RevokeSetupKeyAsync(string id, IReadOnlyList<string> autoGroups, CancellationToken cancellationToken) =>
        ApplyAsync(HttpMethod.Put, ById(SetupKeysPath, id), SetupKeyUpdate(autoGroups, revoked: true), cancellationToken);

    private static JsonObject SetupKeyUpdate(IReadOnlyList<string> autoGroups, bool revoked) => new()
    {
        ["auto_groups"] = NetBirdJson.Strings(autoGroups),
        ["revoked"] = revoked,
    };

    private async Task<NetBirdApiProblem?> ApplyAsync(HttpMethod method, string path, JsonObject? body, CancellationToken cancellationToken)
    {
        var outcome = await api.SendAsync(method, path, body, cancellationToken);
        return outcome switch
        {
            JsonElement => null,
            NetBirdApiProblem problem => problem,
        };
    }

    internal static bool SameSet(IEnumerable<string> left, IEnumerable<string> right) =>
        left.ToHashSet(StringComparer.Ordinal).SetEquals(right);

    private static string ById(string path, string id) => $"{path}/{Uri.EscapeDataString(id)}";

    private static NetBirdGroupsLookup ParseGroups(JsonElement document)
    {
        List<NetBirdGroup> groups = [];
        foreach (var item in document.EnumerateArray())
        {
            if (ParseGroup(item) is not { } group)
            {
                return new NetBirdResponseInvalid("GET /api/groups");
            }

            groups.Add(group);
        }

        return (IReadOnlyList<NetBirdGroup>)groups;
    }

    private static NetBirdGroup? ParseGroup(JsonElement document) =>
        NetBirdJson.Text(document, "name") is { } name && NetBirdJson.Text(document, "id") is { } id ? new NetBirdGroup(name, id) : null;

    private static NetBirdSetupKeysLookup ParseSetupKeys(JsonElement document)
    {
        List<NetBirdSetupKey> keys = [];
        foreach (var item in document.EnumerateArray())
        {
            if (NetBirdJson.Text(item, "id") is not { } id || NetBirdJson.Text(item, "name") is not { } name
                || NetBirdJson.Text(item, "type") is not { } type || NetBirdJson.Boolean(item, "valid") is not { } valid
                || NetBirdJson.Boolean(item, "revoked") is not { } revoked
                || DateTimeOffset.TryParse(NetBirdJson.Text(item, "expires"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var expires) is false)
            {
                return new NetBirdResponseInvalid("GET /api/setup-keys");
            }

            keys.Add(new NetBirdSetupKey(id, name, type, valid, revoked, expires, TextItems(item, "auto_groups")));
        }

        return (IReadOnlyList<NetBirdSetupKey>)keys;
    }

    private static string[] TextItems(JsonElement document, string field) =>
        [.. NetBirdJson.Items(document, field).Select(NetBirdJson.Text).OfType<string>()];

    private sealed record class AccessPolicy(
        string Name, string Protocol, bool Bidirectional, IReadOnlyList<string> Sources, IReadOnlyList<string> Destinations, IReadOnlyList<string> Ports)
    {
        public bool Matches(JsonElement policy) =>
            NetBirdJson.Boolean(policy, "enabled") is true
            && NetBirdJson.Items(policy, "source_posture_checks").Count == 0
            && NetBirdJson.Items(policy, "rules") is [var rule]
            && NetBirdJson.Boolean(rule, "enabled") is true
            && NetBirdJson.Boolean(rule, "bidirectional") == Bidirectional
            && NetBirdJson.Text(rule, "protocol") == Protocol
            && NetBirdJson.Text(rule, "action") == "accept"
            && NetBirdJson.Items(rule, "port_ranges").Count == 0
            && NetBirdJson.Property(rule, "sourceResource").ValueKind is JsonValueKind.Undefined or JsonValueKind.Null
            && NetBirdJson.Property(rule, "destinationResource").ValueKind is JsonValueKind.Undefined or JsonValueKind.Null
            && SameSet(GroupIds(rule, "sources"), Sources)
            && SameSet(GroupIds(rule, "destinations"), Destinations)
            && SameSet(TextItems(rule, "ports"), Ports);

        public JsonObject ToJson(string? ruleId)
        {
            var rule = new JsonObject
            {
                ["name"] = Name,
                ["enabled"] = true,
                ["action"] = "accept",
                ["bidirectional"] = Bidirectional,
                ["protocol"] = Protocol,
                ["sources"] = NetBirdJson.Strings(Sources),
                ["destinations"] = NetBirdJson.Strings(Destinations),
            };
            if (ruleId is not null)
            {
                rule["id"] = ruleId;
            }

            if (Ports.Count > 0)
            {
                rule["ports"] = NetBirdJson.Strings(Ports);
            }

            return new JsonObject
            {
                ["name"] = Name,
                ["enabled"] = true,
                ["source_posture_checks"] = new JsonArray(),
                ["rules"] = new JsonArray(rule),
            };
        }

        private static IEnumerable<string> GroupIds(JsonElement document, string field) =>
            NetBirdJson.Items(document, field).Select(static group => NetBirdJson.Text(group, "id") ?? NetBirdJson.Text(group)).OfType<string>();
    }
}
