namespace TsOrch.Oci;

public closed record class OciEnvironment
{
    public const string MockUrlVariable = "TS_ORCH_OCI_MOCK_URL";
    public const string MockBearerToken = "ts-orch-local";

    public static OciEnvironment FromEnvironment()
    {
        var value = Environment.GetEnvironmentVariable(MockUrlVariable);
        if (string.IsNullOrWhiteSpace(value))
        {
            return new OciCloud();
        }

        var normalized = value.EndsWith('/') ? value : value + "/";
        return Uri.TryCreate(normalized, UriKind.Absolute, out var baseUrl)
            ? new OciMock(baseUrl)
            : throw new InvalidOperationException($"{MockUrlVariable} must be an absolute URL, got '{value}'.");
    }
}

public sealed record class OciCloud : OciEnvironment;

public sealed record class OciMock(Uri BaseUrl) : OciEnvironment;
