namespace TsOrch.Cli;

internal static class ExitCodes
{
    public const int Ok = 0;
    public const int Failure = 1;
    public const int Usage = 64;
    public const int ServiceUnavailable = 69;
    public const int InternalError = 70;
    public const int NoPermission = 77;
    public const int Config = 78;
    public const int Interrupted = 130;

    public static int For(OrchError error) => error switch
    {
        NotFound => Failure,
        Conflict => Failure,
        Validation => Usage,
        Forbidden => NoPermission,
        Unauthorized => NoPermission,
        Unavailable => ServiceUnavailable,
        Internal => InternalError,
    };
}
