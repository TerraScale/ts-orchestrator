namespace TsOrch.Oci;

public closed record class OciEnvironment
{
    public const string MockUrlVariable = "TS_ORCH_OCI_MOCK_URL";
    public const string MockBearerToken = "ts-orch-local";

    public static Result<OciEnvironment, Validation> Resolve(string? mockUrlOverride)
    {
        var (source, value) = mockUrlOverride is null
            ? (MockUrlVariable, Environment.GetEnvironmentVariable(MockUrlVariable))
            : ("--oci-mock-url", mockUrlOverride);
        if (string.IsNullOrWhiteSpace(value))
        {
            return new OciCloud();
        }

        return Uri.TryCreate(value.EndsWith('/') ? value : value + "/", UriKind.Absolute, out var baseUrl)
            ? new OciMock(baseUrl)
            : new Validation($"{source} must be an absolute URL, got '{value}'.");
    }
}

public sealed record class OciCloud : OciEnvironment;

public sealed record class OciMock(Uri BaseUrl) : OciEnvironment;
