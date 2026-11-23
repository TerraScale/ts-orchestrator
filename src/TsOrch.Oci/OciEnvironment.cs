namespace TsOrch.Oci;

public sealed record class InvalidOciMockEndpoint(string Source, string Input)
{
    public string Message => $"{Source} must be an absolute loopback HTTP(S) URL, got '{Input}'.";
}

public readonly union OciEnvironmentResolution(OciEnvironment, InvalidOciMockEndpoint);

public closed record class OciEnvironment
{
    public const string MockUrlVariable = "TS_ORCH_OCI_MOCK_URL";

    public static OciEnvironmentResolution Resolve(string? mockUrlOverride)
    {
        var (source, value) = mockUrlOverride is null
            ? (MockUrlVariable, Environment.GetEnvironmentVariable(MockUrlVariable))
            : ("--oci-mock-url", mockUrlOverride);
        if (string.IsNullOrWhiteSpace(value))
        {
            return new OciCloud();
        }

        return Uri.TryCreate(value.EndsWith('/') ? value : value + "/", UriKind.Absolute, out var baseUrl)
            && baseUrl.IsLoopback && baseUrl.Scheme is "http" or "https" && baseUrl.UserInfo.Length == 0
            ? new OciMock(baseUrl)
            : new InvalidOciMockEndpoint(source, value);
    }
}

public sealed record class OciCloud : OciEnvironment;

public sealed record class OciMock(Uri BaseUrl) : OciEnvironment;
