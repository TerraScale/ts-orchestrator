namespace TsOrch.Protocol;

public closed record class OrchError(string Message);

public sealed record class NotFound(string Message) : OrchError(Message);

public sealed record class Validation(string Message) : OrchError(Message);

public sealed record class Conflict(string Message) : OrchError(Message);

public sealed record class Forbidden(string Message) : OrchError(Message);

public sealed record class Unauthorized(string Message) : OrchError(Message);

public sealed record class Unavailable(string Message) : OrchError(Message);

public sealed record class Internal(string Message) : OrchError(Message);

public readonly record struct Done;

public union OrchResult<T>(T, OrchError);

public sealed record class ErrorDetail(string Code, string Message, string? Fix = null);

public sealed record class ErrorResponse(ErrorDetail Error);

public static class OrchErrorExtensions
{
    extension(OrchError error)
    {
        public string Code => error switch
        {
            NotFound => "not_found",
            Validation => "validation",
            Conflict => "conflict",
            Forbidden => "forbidden",
            Unauthorized => "unauthorized",
            Unavailable => "unavailable",
            Internal => "internal",
        };

        public int HttpStatus => error switch
        {
            NotFound => 404,
            Validation => 400,
            Conflict => 409,
            Forbidden => 403,
            Unauthorized => 401,
            Unavailable => 503,
            Internal => 500,
        };

        public ErrorResponse ToResponse(string? fix) => new(new ErrorDetail(error.Code, error.Message, fix));
    }
}
