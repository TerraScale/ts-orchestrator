using System.Diagnostics.CodeAnalysis;

namespace TsOrch.Cli;

internal static class CliResults
{
    extension<T>(OrchResult<T> result)
        where T : notnull
    {
        public bool TryGetValue([MaybeNullWhen(false)] out T value, [MaybeNullWhen(true)] out OrchError error)
        {
            (value, error) = result switch
            {
                OrchError failure => (default(T), failure),
                T success => (success, (OrchError?)null),
            };
            return error is null;
        }
    }
}
