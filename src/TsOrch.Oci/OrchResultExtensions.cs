using System.Diagnostics.CodeAnalysis;
using TsOrch.Protocol;

namespace TsOrch.Oci;

internal static class OrchResultExtensions
{
    extension<T>(OrchResult<T> result)
    {
        public bool TryGetValue([MaybeNullWhen(false)] out T value, [MaybeNullWhen(true)] out OrchError error)
        {
            (value, error) = result switch
            {
                OrchError failure => (default(T), failure),
                T success => (success, (OrchError?)null),
                null => throw new InvalidOperationException("An uninitialized OrchResult carries no value."),
            };
            return error is null;
        }
    }
}
