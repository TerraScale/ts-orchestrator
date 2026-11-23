using System.Text.Json.Serialization.Metadata;

namespace TsOrch.Cli;

internal readonly union BackplaneFleet(FleetConfig, BackplaneProblem);

internal sealed class OrchApi(OrchHttp http, OperatorAuth auth)
{
    public Task<BackplaneFleet> GetFleetAsync(CancellationToken cancellationToken) =>
        GetAsync("/api/fleet", ApiJsonContext.Default.FleetConfig, static fleet => Task.FromResult<BackplaneFleet>(fleet),
            static problem => problem, cancellationToken);

    public Task<TOutput> GetAsync<T, TOutput>(
        string pathAndQuery, JsonTypeInfo<T> responseType, Func<T, Task<TOutput>> handle, Func<BackplaneProblem, TOutput> fail,
        CancellationToken cancellationToken) where T : class =>
        SendJsonAsync(HttpMethod.Get, pathAndQuery, null, responseType, OrchHttp.DefaultTimeout, handle, fail, cancellationToken);

    public Task<TOutput> PostAsync<TRequest, TResponse, TOutput>(
        string path, TRequest body, JsonTypeInfo<TRequest> requestType, JsonTypeInfo<TResponse> responseType,
        Func<TResponse, Task<TOutput>> handle, Func<BackplaneProblem, TOutput> fail, CancellationToken cancellationToken)
        where TResponse : class =>
        PostAsync(path, body, requestType, responseType, OrchHttp.DefaultTimeout, handle, fail, cancellationToken);

    public Task<TOutput> PostAsync<TRequest, TResponse, TOutput>(
        string path, TRequest body, JsonTypeInfo<TRequest> requestType, JsonTypeInfo<TResponse> responseType, TimeSpan timeout,
        Func<TResponse, Task<TOutput>> handle, Func<BackplaneProblem, TOutput> fail, CancellationToken cancellationToken)
        where TResponse : class =>
        SendJsonAsync(HttpMethod.Post, path, () => OrchHttp.JsonBody(body, requestType), responseType, timeout, handle, fail, cancellationToken);

    public Task<TOutput> PostEmptyAsync<TResponse, TOutput>(
        string path, JsonTypeInfo<TResponse> responseType, Func<TResponse, Task<TOutput>> handle, Func<BackplaneProblem, TOutput> fail,
        CancellationToken cancellationToken) where TResponse : class =>
        SendJsonAsync(HttpMethod.Post, path, null, responseType, OrchHttp.DefaultTimeout, handle, fail, cancellationToken);

    public Task<TOutput> DeleteAsync<TResponse, TOutput>(
        string path, JsonTypeInfo<TResponse> responseType, Func<TResponse, Task<TOutput>> handle, Func<BackplaneProblem, TOutput> fail,
        CancellationToken cancellationToken) where TResponse : class =>
        SendJsonAsync(HttpMethod.Delete, path, null, responseType, OrchHttp.DefaultTimeout, handle, fail, cancellationToken);

    public Task<BackplaneText> GetTextAsync(string pathAndQuery, CancellationToken cancellationToken) =>
        SendAuthenticatedAsync(HttpMethod.Get, pathAndQuery, null,
            (request, token) => http.SendTextAsync(request, OrchHttp.DefaultTimeout, token),
            static failure => new BackplaneAuthenticationFailed(failure), cancellationToken);

    public Task<BackplaneStream> StreamAsync<T>(
        string pathAndQuery, JsonTypeInfo<T> itemType, Func<T, CancellationToken, Task> onItem, CancellationToken cancellationToken) where T : class =>
        SendAuthenticatedAsync(HttpMethod.Get, pathAndQuery, null,
            (request, token) => http.StreamJsonLinesAsync(request, itemType, onItem, token),
            static failure => new BackplaneAuthenticationFailed(failure), cancellationToken);

    private Task<TOutput> SendJsonAsync<T, TOutput>(
        HttpMethod method, string pathAndQuery, Func<HttpContent>? content, JsonTypeInfo<T> responseType, TimeSpan timeout,
        Func<T, Task<TOutput>> handle, Func<BackplaneProblem, TOutput> fail, CancellationToken cancellationToken) where T : class =>
        SendAuthenticatedAsync(method, pathAndQuery, content,
            (request, token) => http.SendJsonAsync(request, responseType, timeout, handle, fail, token),
            failure => fail(new BackplaneAuthenticationFailed(failure)), cancellationToken);

    private async Task<TOutput> SendAuthenticatedAsync<TOutput>(
        HttpMethod method, string pathAndQuery, Func<HttpContent>? content,
        Func<HttpRequestMessage, CancellationToken, Task<TOutput>> send, Func<CliDiagnostic, TOutput> fail, CancellationToken cancellationToken)
    {
        var outcome = await auth.GetAsync(cancellationToken);
        return outcome switch
        {
            OperatorCredentials credentials => await SendAsync(credentials, method, pathAndQuery, content, send, cancellationToken),
            InvalidBackplaneUrl invalid => fail(CliDiagnostic.Usage(invalid.Message)),
            OperatorKeyMissing missing => fail(CliDiagnostic.Permission(missing.Message)),
            OperatorSignInFailed failed => fail(failed.Diagnostic),
        };
    }

    private static async Task<TOutput> SendAsync<TOutput>(OperatorCredentials credentials, HttpMethod method, string pathAndQuery,
        Func<HttpContent>? content, Func<HttpRequestMessage, CancellationToken, Task<TOutput>> send, CancellationToken cancellationToken)
    {
        using var request = OrchHttp.CreateRequest(method, credentials.BaseUrl, pathAndQuery, credentials.Token, content?.Invoke());
        return await send(request, cancellationToken);
    }
}
