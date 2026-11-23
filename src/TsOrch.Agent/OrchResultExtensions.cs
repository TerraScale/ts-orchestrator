using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace TsOrch.Agent;

public static class OrchResultExtensions
{
    extension<T>(OrchResult<T> result)
    {
        public bool TryGetValue([MaybeNullWhen(false)] out T value, [MaybeNullWhen(true)] out OrchError error)
        {
            switch (result)
            {
                case OrchError failure:
                    value = default;
                    error = failure;
                    return false;
                case T success:
                    value = success;
                    error = null;
                    return true;
                default:
                    throw new UnreachableException();
            }
        }
    }
}
