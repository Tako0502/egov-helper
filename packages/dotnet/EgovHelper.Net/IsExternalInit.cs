// `init` accessor support for older target frameworks (netstandard2.1).
// This class is provided in-box on .NET 5+, but netstandard2.1 needs us to declare it.
// See: https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/proposals/csharp-9.0/init

#if !NET5_0_OR_GREATER
namespace System.Runtime.CompilerServices
{
    using System.ComponentModel;

    [EditorBrowsable(EditorBrowsableState.Never)]
    internal static class IsExternalInit { }
}
#endif
