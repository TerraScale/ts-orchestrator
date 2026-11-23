using System.Text.Json.Serialization.Metadata;

namespace TsOrch.Cli;

internal sealed class OrchApi(OrchHttp http, OperatorAuth auth)
{
    public async Task<Result<T, Validation, NotFound, Unauthorized, Forbidden, Unavailable>> GetAsync<T>(
        string pathAndQuery,
        JsonTypeInfo<T> responseType,
        CancellationToken cancellationToken)
        where T : notnull =>
        await SendJsonAsync(HttpMethod.Get, pathAndQuery, content: null, responseType, OrchHttp.DefaultTimeout, cancellationToken) switch
        {
            T value => value,
            Validation failure => failure,
            NotFound failure => failure,
            Conflict failure => UnexpectedConflict(failure),
            Unauthorized failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
        };

    public Task<Result<TResponse, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>> PostAsync<TRequest, TResponse>(
        string path,
        TRequest body,
        JsonTypeInfo<TRequest> requestType,
        JsonTypeInfo<TResponse> responseType,
        CancellationToken cancellationToken)
        where TResponse : notnull =>
        PostAsync(path, body, requestType, responseType, OrchHttp.DefaultTimeout, cancellationToken);

    public Task<Result<TResponse, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>> PostAsync<TRequest, TResponse>(
        string path,
        TRequest body,
        JsonTypeInfo<TRequest> requestType,
        JsonTypeInfo<TResponse> responseType,
        TimeSpan timeout,
        CancellationToken cancellationToken)
        where TResponse : notnull =>
        SendJsonAsync(HttpMethod.Post, path, () => OrchHttp.JsonBody(body, requestType), responseType, timeout, cancellationToken);

    public Task<Result<TResponse, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>> PostEmptyAsync<TResponse>(
        string path,
        JsonTypeInfo<TResponse> responseType,
        CancellationToken cancellationToken)
        where TResponse : notnull =>
        SendJsonAsync(HttpMethod.Post, path, content: null, responseType, OrchHttp.DefaultTimeout, cancellationToken);

    public Task<Result<TResponse, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>> DeleteAsync<TResponse>(
        string path,
        JsonTypeInfo<TResponse> responseType,
        CancellationToken cancellationToken)
        where TResponse : notnull =>
        SendJsonAsync(HttpMethod.Delete, path, content: null, responseType, OrchHttp.DefaultTimeout, cancellationToken);

    public async Task<Result<string, Validation, NotFound, Unauthorized, Forbidden, Unavailable>> GetTextAsync(string pathAndQuery, CancellationToken cancellationToken) =>
        await auth.GetAsync(cancellationToken) switch
        {
            OperatorCredentials credentials => await GetTextAsync(credentials, pathAndQuery, cancellationToken) switch
            {
                string text => text,
                Validation failure => failure,
                NotFound failure => failure,
                Conflict failure => UnexpectedConflict(failure),
                Unauthorized failure => failure,
                Forbidden failure => failure,
                Unavailable failure => failure,
            },
            Validation failure => failure,
            Unauthorized failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
        };

    public async Task<Result<Done, Validation, NotFound, Unauthorized, Forbidden, Unavailable>> StreamAsync<T>(
        string pathAndQuery,
        JsonTypeInfo<T> itemType,
        Func<T, CancellationToken, Task> onItem,
        CancellationToken cancellationToken)
        where T : notnull =>
        await auth.GetAsync(cancellationToken) switch
        {
            OperatorCredentials credentials => await StreamAsync(credentials, pathAndQuery, itemType, onItem, cancellationToken) switch
            {
                Done done => done,
                Validation failure => failure,
                NotFound failure => failure,
                Conflict failure => UnexpectedConflict(failure),
                Unauthorized failure => failure,
                Forbidden failure => failure,
                Unavailable failure => failure,
            },
            Validation failure => failure,
            Unauthorized failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
        };

    private static Unavailable UnexpectedConflict(Conflict conflict) =>
        new($"The backplane answered a read with an unexpected conflict: {conflict.Message}");

    private async Task<Result<string, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>> GetTextAsync(
        OperatorCredentials credentials,
        string pathAndQuery,
        CancellationToken cancellationToken)
    {
        using var request = OrchHttp.CreateRequest(HttpMethod.Get, credentials.BaseUrl, pathAndQuery, credentials.Token, content: null);
        return await http.SendTextAsync(request, OrchHttp.DefaultTimeout, cancellationToken);
    }

    private async Task<Result<Done, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>> StreamAsync<T>(
        OperatorCredentials credentials,
        string pathAndQuery,
        JsonTypeInfo<T> itemType,
        Func<T, CancellationToken, Task> onItem,
        CancellationToken cancellationToken)
        where T : notnull
    {
        using var request = OrchHttp.CreateRequest(HttpMethod.Get, credentials.BaseUrl, pathAndQuery, credentials.Token, content: null);
        return await http.StreamJsonLinesAsync(request, itemType, onItem, cancellationToken);
    }

    private async Task<Result<T, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>> SendJsonAsync<T>(
        HttpMethod method,
        string pathAndQuery,
        Func<HttpContent>? content,
        JsonTypeInfo<T> responseType,
        TimeSpan timeout,
        CancellationToken cancellationToken)
        where T : notnull =>
        await auth.GetAsync(cancellationToken) switch
        {
            OperatorCredentials credentials => await SendJsonAsync(credentials, method, pathAndQuery, content, responseType, timeout, cancellationToken),
            Validation failure => failure,
            Unauthorized failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
        };

    private async Task<Result<T, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>> SendJsonAsync<T>(
        OperatorCredentials credentials,
        HttpMethod method,
        string pathAndQuery,
        Func<HttpContent>? content,
        JsonTypeInfo<T> responseType,
        TimeSpan timeout,
        CancellationToken cancellationToken)
        where T : notnull
    {
        using var request = OrchHttp.CreateRequest(method, credentials.BaseUrl, pathAndQuery, credentials.Token, content?.Invoke());
        return await http.SendJsonAsync(request, responseType, timeout, cancellationToken);
    }
}
