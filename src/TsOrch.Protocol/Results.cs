namespace TsOrch.Protocol;

public readonly union Result<T, T1>(T, T1);

public readonly union Result<T, T1, T2>(T, T1, T2);

public readonly union Result<T, T1, T2, T3>(T, T1, T2, T3);

public readonly union Result<T, T1, T2, T3, T4>(T, T1, T2, T3, T4);

public readonly union Result<T, T1, T2, T3, T4, T5>(T, T1, T2, T3, T4, T5);

public readonly union Result<T, T1, T2, T3, T4, T5, T6>(T, T1, T2, T3, T4, T5, T6);

public readonly record struct Done;

public sealed record class NotFound(string Message, string Code = "not_found");

public sealed record class Validation(string Message, string Code = "validation");

public sealed record class Conflict(string Message, string Code = "conflict");

public sealed record class PreconditionFailed(string Message, string Code = "precondition_failed");

public sealed record class Unauthorized(string Message, string Code = "unauthorized");

public sealed record class Forbidden(string Message, string Code = "forbidden");

public sealed record class QuotaExceeded(string Message, string Code = "quota_exceeded");

public sealed record class Unavailable(string Message, string Code = "unavailable");

public sealed record class PayloadTooLarge(string Message, string Code = "payload_too_large");

public sealed record class UnsupportedMediaType(string Message, string Code = "unsupported_media_type");

public sealed record class RequestTimeout(string Message, string Code = "request_timeout");

public sealed record class Gone(string Message, string Code = "gone");

public sealed record class InternalFailure(string Message, string Code = "internal");

public sealed record class ErrorDetail(string Code, string Message, string? Fix = null);

public sealed record class ErrorResponse(ErrorDetail Error);
