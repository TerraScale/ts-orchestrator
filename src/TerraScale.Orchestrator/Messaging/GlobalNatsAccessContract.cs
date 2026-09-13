using System.Collections.ObjectModel;
using TerraScale.Orchestrator;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// Names the capability selected by a global-control identity. The account is
/// derived from the capability, not from a credential supplied by a caller.
/// </summary>
internal enum GlobalNatsCapability
{
    CellDirectoryPublisher,
    CellDirectoryReader,
    CellDirectoryService,
    GlobalAuthority
}

internal enum GlobalNatsAccountKind
{
    GlobalAuthority,
    GlobalDirectory,
    RegionalControl
}

internal sealed record GlobalNatsAccountDescriptor(
    GlobalNatsAccountKind Kind,
    string Name);

internal sealed record GlobalNatsServiceExport(string Subject);

internal sealed record GlobalNatsServiceImport(
    string Subject,
    string SourceAccount);

internal sealed class GlobalNatsAccessPlan
{
    internal GlobalNatsAccessPlan(
        string cell,
        GlobalNatsCapability capability,
        GlobalNatsAccountDescriptor account,
        GlobalNatsPermissionPlan permissions,
        IEnumerable<GlobalNatsServiceImport> imports,
        IEnumerable<GlobalNatsServiceExport> exports)
    {
        Cell = cell;
        Capability = capability;
        Account = account;
        Permissions = permissions;
        Imports = Array.AsReadOnly(imports.ToArray());
        Exports = Array.AsReadOnly(exports.ToArray());
    }

    internal string Cell { get; }
    internal GlobalNatsCapability Capability { get; }
    internal GlobalNatsAccountDescriptor Account { get; }
    internal GlobalNatsPermissionPlan Permissions { get; }
    internal ReadOnlyCollection<GlobalNatsServiceImport> Imports { get; }
    internal ReadOnlyCollection<GlobalNatsServiceExport> Exports { get; }

    internal ReadOnlyCollection<string> Publish => Permissions.Publish;
    internal ReadOnlyCollection<string> Subscribe => Permissions.Subscribe;
}

/// <summary>
/// Pure account and cross-account access policy for the global directory.
/// It returns names and allowlists only. Credential, account-JWT, and NATS
/// adapter code consume this plan later.
/// </summary>
internal static class GlobalNatsAccessContract
{
    internal static GlobalNatsAccessPlan Create(
        string cell,
        GlobalNatsCapability capability)
    {
        ValidateCell(cell);
        if (capability == GlobalNatsCapability.CellDirectoryService && cell != "gru")
            throw new ArgumentException(
                "The global directory service capability is GRU-only.",
                nameof(cell));
        if (capability == GlobalNatsCapability.GlobalAuthority)
            GlobalNatsConfiguration.ValidateLegacyAuthorityAlias(cell);

        var role = capability switch
        {
            GlobalNatsCapability.CellDirectoryPublisher => GlobalNatsRole.CellDirectoryPublisher,
            GlobalNatsCapability.CellDirectoryReader => GlobalNatsRole.CellDirectoryReader,
            GlobalNatsCapability.CellDirectoryService => GlobalNatsRole.CellDirectoryService,
            GlobalNatsCapability.GlobalAuthority => GlobalNatsRole.GlobalAuthority,
            _ => throw new ArgumentOutOfRangeException(nameof(capability), capability, "Unknown global NATS capability.")
        };
        var account = AccountFor(cell, capability);
        var permissions = GlobalNatsPermissions.Create(cell, role);
        IEnumerable<GlobalNatsServiceImport> imports = capability == GlobalNatsCapability.CellDirectoryReader
            ? [new GlobalNatsServiceImport(
                GlobalNatsTopology.CellDirectorySubject,
                GlobalNatsAccountNames.GlobalDirectory)]
            : [];
        IEnumerable<GlobalNatsServiceExport> exports = capability == GlobalNatsCapability.CellDirectoryService
            ? [new GlobalNatsServiceExport(GlobalNatsTopology.CellDirectorySubject)]
            : [];
        return new(cell, capability, account, permissions, imports, exports);
    }

    internal static GlobalNatsAccessPlan Create(
        string cell,
        GlobalNatsRole role) =>
        Create(cell, role switch
        {
            GlobalNatsRole.CellDirectoryPublisher => GlobalNatsCapability.CellDirectoryPublisher,
            GlobalNatsRole.CellDirectoryReader => GlobalNatsCapability.CellDirectoryReader,
            GlobalNatsRole.CellDirectoryService => GlobalNatsCapability.CellDirectoryService,
            GlobalNatsRole.GlobalAuthority => GlobalNatsCapability.GlobalAuthority,
            _ => throw new ArgumentOutOfRangeException(nameof(role), role, "Unknown global NATS role.")
        });

    private static GlobalNatsAccountDescriptor AccountFor(
        string cell,
        GlobalNatsCapability capability) =>
        capability switch
        {
            GlobalNatsCapability.GlobalAuthority =>
                new(GlobalNatsAccountKind.GlobalAuthority, GlobalNatsAccountNames.GlobalAuthority),
            GlobalNatsCapability.CellDirectoryPublisher or
                GlobalNatsCapability.CellDirectoryService =>
                new(GlobalNatsAccountKind.GlobalDirectory, GlobalNatsAccountNames.GlobalDirectory),
            GlobalNatsCapability.CellDirectoryReader =>
                new(GlobalNatsAccountKind.RegionalControl, GlobalNatsAccountNames.RegionalControl(cell)),
            _ => throw new ArgumentOutOfRangeException(nameof(capability), capability, "Unknown global NATS capability.")
        };

    private static void ValidateCell(string cell)
    {
        if (!CellTokenRule.IsValid(cell))
            throw new ArgumentException(
                "The global NATS access cell is not a lowercase DNS-style token.",
                nameof(cell));
    }
}

internal static class GlobalNatsAccountNames
{
    internal const string GlobalAuthority = "ts-orch-global-authority";
    internal const string GlobalDirectory = "ts-orch-global-directory";

    internal static string RegionalControl(string cell)
    {
        if (!CellTokenRule.IsValid(cell))
            throw new ArgumentException(
                "The regional NATS account cell is not a lowercase DNS-style token.",
                nameof(cell));
        var account = $"ts-orch-regional-control-{cell}";
        if (!IsValid(account))
            throw new InvalidOperationException("The generated regional NATS account name is invalid.");
        return account;
    }

    internal static bool IsValid(string? account) =>
        account is { Length: >= 1 and <= 128 } &&
        account[0] != '-' && account[^1] != '-' &&
        account.All(static character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');
}

