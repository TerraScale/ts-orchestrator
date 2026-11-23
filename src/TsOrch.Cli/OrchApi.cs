using System.Text.Json.Serialization.Metadata;

namespace TsOrch.Cli;

internal sealed class OrchApi(OrchHttp http, OperatorAuth auth)
{
    public Task<OrchResult<T>> GetAsync<T>(string pathAndQuery, JsonTypeInfo<T> responseType, CancellationToken cancellationToken)
        where T : notnull =>
        SendJsonAsync(HttpMethod.Get, pathAndQuery, content: null, responseType, OrchHttp.DefaultTimeout, cancellationToken);

    public Task<OrchResult<TResponse>> PostAsync<TRequest, TResponse>(
        string path,
        TRequest body,
        JsonTypeInfo<TRequest> requestType,
        JsonTypeInfo<TResponse> responseType,
        CancellationToken cancellationToken)
        where TResponse : notnull =>
        PostAsync(path, body, requestType, responseType, OrchHttp.DefaultTimeout, cancellationToken);

    public Task<OrchResult<TResponse>> PostAsync<TRequest, TResponse>(
        string path,
        TRequest body,
        JsonTypeInfo<TRequest> requestType,
        JsonTypeInfo<TResponse> responseType,
        TimeSpan timeout,
        CancellationToken cancellationToken)
        where TResponse : notnull =>
        SendJsonAsync(HttpMethod.Post, path, () => OrchHttp.JsonBody(body, requestType), responseType, timeout, cancellationToken);

    public Task<OrchResult<TResponse>> PostEmptyAsync<TResponse>(string path, JsonTypeInfo<TResponse> responseType, CancellationToken cancellationToken)
        where TResponse : notnull =>
        SendJsonAsync(HttpMethod.Post, path, content: null, responseType, OrchHttp.DefaultTimeout, cancellationToken);

    public Task<OrchResult<TResponse>> DeleteAsync<TResponse>(string path, JsonTypeInfo<TResponse> responseType, CancellationToken cancellationToken)
        where TResponse : notnull =>
        SendJsonAsync(HttpMethod.Delete, path, content: null, responseType, OrchHttp.DefaultTimeout, cancellationToken);

    public async Task<OrchResult<string>> GetTextAsync(string pathAndQuery, CancellationToken cancellationToken)
    {
        if (!(await auth.GetAsync(cancellationToken)).TryGetValue(out var credentials, out var error))
        {
            return error;
        }

        using var request = OrchHttp.CreateRequest(HttpMethod.Get, credentials.BaseUrl, pathAndQuery, credentials.Token, content: null);
        return await http.SendTextAsync(request, OrchHttp.DefaultTimeout, cancellationToken);
    }

    public async Task<OrchResult<string>> PostTextAsync<TRequest>(string path, TRequest body, JsonTypeInfo<TRequest> requestType, CancellationToken cancellationToken)
    {
        if (!(await auth.GetAsync(cancellationToken)).TryGetValue(out var credentials, out var error))
        {
            return error;
        }

        using var request = OrchHttp.CreateRequest(HttpMethod.Post, credentials.BaseUrl, path, credentials.Token, OrchHttp.JsonBody(body, requestType));
        return await http.SendTextAsync(request, OrchHttp.DefaultTimeout, cancellationToken);
    }

    public async Task<OrchResult<Done>> StreamAsync<T>(
        string pathAndQuery,
        JsonTypeInfo<T> itemType,
        Func<T, CancellationToken, Task> onItem,
        CancellationToken cancellationToken)
        where T : notnull
    {
        if (!(await auth.GetAsync(cancellationToken)).TryGetValue(out var credentials, out var error))
        {
            return error;
        }

        using var request = OrchHttp.CreateRequest(HttpMethod.Get, credentials.BaseUrl, pathAndQuery, credentials.Token, content: null);
        return await http.StreamJsonLinesAsync(request, itemType, onItem, cancellationToken);
    }

    private async Task<OrchResult<T>> SendJsonAsync<T>(
        HttpMethod method,
        string pathAndQuery,
        Func<HttpContent>? content,
        JsonTypeInfo<T> responseType,
        TimeSpan timeout,
        CancellationToken cancellationToken)
        where T : notnull
    {
        if (!(await auth.GetAsync(cancellationToken)).TryGetValue(out var credentials, out var error))
        {
            return error;
        }

        using var request = OrchHttp.CreateRequest(method, credentials.BaseUrl, pathAndQuery, credentials.Token, content?.Invoke());
        return await http.SendJsonAsync(request, responseType, timeout, cancellationToken);
    }
}
