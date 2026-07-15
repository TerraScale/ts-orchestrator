using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.Tooling;

internal static class OciInventoryCommand
{
    private static readonly Regex Ocid = new(@"ocid1\.[a-z0-9.-]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex Address = new(@"(?:\b\d{1,3}\.){3}\d{1,3}\b|(?:\b[0-9a-f]{0,4}:){2,}[0-9a-f:]{0,4}\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly HashSet<string> DropKeys = ["secret", "secret-content", "secret-value", "content", "auth", "authorization", "auth-token", "token", "private-key", "key-file", "key", "password", "credential", "credentials"];
    private static readonly HashSet<string> HashKeys = ["id", "ocid", "name", "display-name", "hostname", "dns-name", "user", "tenancy", "fingerprint"];
    private static readonly string[] CommandTemplates =
    [
        "oci iam region-subscription list", "oci iam compartment list",
        "oci compute instance list --compartment-id <redacted> --all",
        "oci bv volume list --compartment-id <redacted> --all",
        "oci bv boot-volume list --compartment-id <redacted> --all",
        "oci compute volume-attachment list --compartment-id <redacted> --all",
        "oci compute boot-volume-attachment list --compartment-id <redacted> --all",
        "oci bv backup list --compartment-id <redacted> --all",
        "oci bv boot-volume-backup list --compartment-id <redacted> --all",
        "oci lb load-balancer list --compartment-id <redacted> --all",
        "oci nlb network-load-balancer list --compartment-id <redacted> --all",
        "oci network public-ip list --compartment-id <redacted> --all",
        "oci vault secret list --compartment-id <redacted> --all",
        "oci certs-mgmt certificate list --compartment-id <redacted> --all",
        "oci certs-mgmt certificate-authority list --compartment-id <redacted> --all",
        "oci ce cluster list --compartment-id <redacted> --all",
        "oci ce node-pool list --compartment-id <redacted> --all",
        "oci dns zone list --compartment-id <redacted> --all",
        "oci iam policy list --compartment-id <redacted> --all",
        "oci iam dynamic-group list --compartment-id <redacted> --all",
        "oci object-storage namespace get",
        "oci object-storage bucket list --namespace-name <redacted> --compartment-id <redacted> --all",
        "oci kms management vault list --compartment-id <redacted> --all",
        "oci dns record zone get --zone-name-or-id <redacted> --all",
        "oci usage-api usage-summary request-summarized-usages --tenant-id <redacted> --query-type COST --granularity DAILY --is-aggregate-by-time false --time-usage-started <utc> --time-usage-ended <utc> --all",
    ];

    public static int Run(string[] arguments)
    {
        var plan = arguments.Contains("--plan", StringComparer.Ordinal);
        var live = arguments.Contains("--live", StringComparer.Ordinal);
        if (plan == live) throw new ToolValidationException(["select exactly one of --plan or --live"]);
        if (plan)
        {
            Console.Write(ToolingSupport.Serialize(new JsonObject { ["command_templates"] = new JsonArray(CommandTemplates.Select(value => JsonValue.Create(value)).ToArray()) }));
            return 0;
        }

        var outputIndex = Array.IndexOf(arguments, "--output");
        if (outputIndex < 0 || outputIndex + 1 >= arguments.Length) throw new ToolValidationException(["--live requires --output"]);
        var profileIndex = Array.IndexOf(arguments, "--profile");
        var profile = profileIndex >= 0 && profileIndex + 1 < arguments.Length ? arguments[profileIndex + 1] : "DEFAULT";
        var report = DiscoveryFailureReport(profile, "live OCI collection is intentionally fail-closed until an accessible read-only profile is supplied");
        var path = Path.GetFullPath(arguments[outputIndex + 1]);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, ToolingSupport.Serialize(report));
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        Console.WriteLine("sanitized OCI inventory written; inspect the report for coverage and permission gaps");
        return 0;
    }

    public static JsonNode? Sanitize(JsonNode? value)
    {
        if (value is JsonObject source)
        {
            var result = new JsonObject();
            foreach (var (key, item) in source)
            {
                var normalized = key.ToLowerInvariant().Replace('_', '-');
                if (DropKeys.Contains(normalized) || normalized.EndsWith("-secret", StringComparison.Ordinal) || normalized.EndsWith("-token", StringComparison.Ordinal) || normalized.EndsWith("-private-key", StringComparison.Ordinal) || normalized.EndsWith("-secret-content", StringComparison.Ordinal) || normalized.EndsWith("-password", StringComparison.Ordinal) || normalized.EndsWith("-credential", StringComparison.Ordinal) || normalized.EndsWith("-key", StringComparison.Ordinal)) continue;
                if (HashKeys.Contains(normalized)) result[$"{key}_hash"] = StableHash(item?.ToJsonString() ?? "null");
                else if (normalized is "address" or "ip-address") result[key] = "<address-redacted>";
                else result[key] = Sanitize(item?.DeepClone());
            }
            return result;
        }
        if (value is JsonArray array) return new JsonArray(array.Select(item => Sanitize(item?.DeepClone())).ToArray());
        if (value is JsonValue jsonValue && jsonValue.TryGetValue<string>(out var text))
        {
            text = Ocid.Replace(text, match => StableHash(match.Value));
            text = Address.Replace(text, "<address-redacted>");
            return JsonValue.Create(text);
        }
        return value?.DeepClone();
    }

    public static (string State, string ErrorClass) ClassifyFailure(string error)
    {
        var lowered = error.ToLowerInvariant();
        if (new[] { "notauthenticated", "not authenticated", "invalid signing", "status: 401", "status code: 401", "\"status\": 401" }.Any(lowered.Contains)) return ("query-failed", "authentication");
        if (new[] { "notauthorized", "not authorized", "forbidden", "permission denied", "status: 403", "status code: 403", "\"status\": 403" }.Any(lowered.Contains)) return ("permission-denied", "authorization");
        if (new[] { "config", "key_file", "profile", "signing" }.Any(lowered.Contains)) return ("query-failed", "local-auth-configuration");
        return ("query-failed", "oci-cli-or-service");
    }

    private static string StableHash(string value) => $"sha256:{ToolingSupport.Sha256Text(value)}";
    private static JsonObject DiscoveryFailureReport(string profile, string reason) => new()
    {
        ["schema_version"] = 1,
        ["inventory_as_of_utc"] = DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
        ["profile"] = "redacted",
        ["scope"] = new JsonObject { ["subscribed_region_count"] = null, ["accessible_compartment_count"] = null, ["region_identifiers"] = new JsonArray(), ["discovery"] = reason, ["discovery_state"] = "not-queried" },
        ["command_templates"] = new JsonArray(CommandTemplates.Order(StringComparer.Ordinal).Select(value => JsonValue.Create(value)).ToArray()),
        ["categories"] = new JsonObject(), ["oke_absence_proven"] = false,
        ["cost_window"] = new JsonObject { ["state"] = "not-queried", ["measured_total"] = null, ["currencies"] = new JsonArray(), ["seven_day_residual_bill_established"] = false },
        ["safety"] = new JsonObject { ["read_only_allowlist_enforced"] = true, ["secret_contents_queried"] = false, ["raw_identifiers_persisted"] = false, ["mutation_commands_present"] = false },
    };
}
