using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// The closed catalog of cross-account, cross-region exchanges the gateway
/// supercluster may carry: only approved, versioned control services from the
/// canonical taxonomy. Nothing grants direct access to authority, CI, release,
/// Object Store, regional journal, platform-API, or product subjects, and an
/// import or export that is not the exact approved subject fails closed.
/// </summary>
internal static class NatsGatewayServiceCatalog
{
    /// <summary>
    /// The only approved cross-account service today: the versioned global
    /// cell directory query service under the v1 control root.
    /// </summary>
    internal static readonly IReadOnlyList<string> ApprovedServices = [GlobalNatsTopology.CellDirectorySubject];

    /// <summary>
    /// The one account each approved service may be exported by — the typed
    /// exporter expectation. Any other account exporting an approved subject,
    /// even a declared one, is rejected.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> ApprovedExporters =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [GlobalNatsTopology.CellDirectorySubject] = GlobalNatsAccountNames.GlobalDirectory,
        };

    /// <summary>Asset-name prefixes that belong to the GRU global authority scope only.</summary>
    internal static readonly IReadOnlyList<string> GlobalAuthorityAssetPrefixes = ["GLOBAL_", "CI_"];

    internal static bool IsApprovedService(string subject) =>
        ApprovedServices.Contains(subject, StringComparer.Ordinal);

    /// <summary>The account that must export an approved subject; empty for unapproved subjects.</summary>
    internal static string ExpectedExporter(string subject) =>
        ApprovedExporters.TryGetValue(subject, out var exporter) ? exporter : string.Empty;

    /// <summary>
    /// Explains why a subject can never be imported or exported. Returns false
    /// only for the exact approved services.
    /// </summary>
    internal static bool TryDeny(string subject, out string reason)
    {
        reason = string.Empty;
        if (string.IsNullOrEmpty(subject))
        {
            reason = "The exchange subject is empty.";
            return true;
        }
        if (subject.Contains('*') || subject.Contains('>'))
        {
            reason = $"The exchange subject '{subject}' is a wildcard; exchanges are exact subjects only.";
            return true;
        }
        if (IsApprovedService(subject))
        {
            return false;
        }

        reason = NatsSubjectTaxonomy.Classify(subject) switch
        {
            NatsSubjectNamespace.PlatformReserved =>
                $"The subject '{subject}' is a platform-reserved subject; JetStream and system APIs never cross accounts through the gateway.",
            NatsSubjectNamespace.ProductPlane =>
                $"The subject '{subject}' belongs to the product plane; product subjects never traverse a control gateway.",
            NatsSubjectNamespace.GlobalAuthority =>
                $"The subject '{subject}' is a global-authority subject; authority journals never cross accounts through the gateway.",
            NatsSubjectNamespace.ContinuousIntegration =>
                $"The subject '{subject}' is a CI subject; CI subjects never cross accounts through the gateway.",
            NatsSubjectNamespace.GlobalDirectory =>
                $"The subject '{subject}' is a directory subject but not an approved versioned service exchange.",
            NatsSubjectNamespace.Audit =>
                $"The subject '{subject}' is an audit subject; audit subjects never cross accounts through the gateway.",
            NatsSubjectNamespace.RegionalControl =>
                $"The subject '{subject}' is a regional control subject of one cell; regional subjects never cross accounts through the gateway.",
            NatsSubjectNamespace.Operations =>
                $"The subject '{subject}' is a regional journal subject; regional journals never cross accounts through the gateway.",
            NatsSubjectNamespace.Agent =>
                $"The subject '{subject}' is a regional agent subject; agent subjects never cross accounts through the gateway.",
            _ =>
                $"The subject '{subject}' is outside the closed control taxonomy; unknown subjects fail closed.",
        };
        return true;
    }

    /// <summary>Validates one export; an empty list is the only passing result.</summary>
    internal static IReadOnlyList<string> ValidateExport(NatsGatewayPlan plan, NatsGatewayServiceExport export)
    {
        var errors = new List<string>();
        if (TryDeny(export.Subject, out var reason))
            errors.Add($"The export on '{export.Subject}' is denied: {reason}");
        else
        {
            // The subject is approved, so its exporter is pinned: only the
            // typed expectation may hold the export, and no other declared
            // account can stand in front of the service.
            var expectedExporter = ExpectedExporter(export.Subject);
            if (export.AccountName != expectedExporter)
                errors.Add(
                    $"The export on '{export.Subject}' must be exported by the account '{expectedExporter}', not '{export.AccountName}'.");
        }
        if (plan.Accounts.All(scope => scope.AccountName != export.AccountName))
            errors.Add($"The exporting account '{export.AccountName}' is not declared in the plan.");
        return errors;
    }

    /// <summary>Validates one import; an empty list is the only passing result.</summary>
    internal static IReadOnlyList<string> ValidateImport(NatsGatewayPlan plan, NatsGatewayServiceImport import)
    {
        var errors = new List<string>();
        if (TryDeny(import.Subject, out var reason))
            errors.Add($"The import on '{import.Subject}' is denied: {reason}");
        if (plan.Accounts.All(scope => scope.AccountName != import.AccountName))
            errors.Add($"The importing account '{import.AccountName}' is not declared in the plan.");
        if (plan.Accounts.All(scope => scope.AccountName != import.SourceAccountName))
            errors.Add($"The source account '{import.SourceAccountName}' is not declared in the plan.");
        if (!plan.Exports.Any(export =>
                export.Subject == import.Subject && export.AccountName == import.SourceAccountName))
            errors.Add(
                $"The import on '{import.Subject}' has no matching export from account '{import.SourceAccountName}'.");
        return errors;
    }
}

