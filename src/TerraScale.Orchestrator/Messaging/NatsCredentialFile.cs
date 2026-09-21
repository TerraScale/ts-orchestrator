namespace TerraScale.Orchestrator.Messaging;

internal static class NatsCredentialFile
{
    public static string? Resolve(string? value, string optionName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }
        var path = NatsFileResolver.Resolve(value, optionName, 4096, ownerPrivate: true);
        try
        {
            _ = NATS.Client.Core.NKeys.PublicKeyFromSeed(Seed(path));
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        {
            throw new ArgumentException($"{optionName} does not contain a valid NKey seed.", exception);
        }
        return path;
    }

    internal static bool SameIdentity(string first, string second) =>
        NATS.Client.Core.NKeys.PublicKeyFromSeed(Seed(first)) ==
        NATS.Client.Core.NKeys.PublicKeyFromSeed(Seed(second));

    internal static string PublicKey(string path) => NATS.Client.Core.NKeys.PublicKeyFromSeed(Seed(path));

    internal static string Seed(string path) => File.ReadLines(path)
        .FirstOrDefault(static line => !string.IsNullOrWhiteSpace(line))
        ?? throw new ArgumentException("NKey seed file is empty.");
}
