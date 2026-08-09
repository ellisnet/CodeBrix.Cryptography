namespace CodeBrix.Cryptography.Runtime.Intrinsics.X86; //was previously: Org.BouncyCastle.Runtime.Intrinsics.X86;

internal static class Pclmulqdq
{
    internal static bool IsEnabled => System.Runtime.Intrinsics.X86.Pclmulqdq.IsSupported;

    internal static class V256
    {
        internal static bool IsEnabled => System.Runtime.Intrinsics.X86.Pclmulqdq.V256.IsSupported;
    }

    internal static class V512
    {
        internal static bool IsEnabled => System.Runtime.Intrinsics.X86.Pclmulqdq.V512.IsSupported;
    }

//        internal static class X64
//        {
//#if NETCOREAPP3_0_OR_GREATER
//            internal static bool IsEnabled => System.Runtime.Intrinsics.X86.Pclmulqdq.X64.IsSupported;
//#else
//            internal static bool IsEnabled => false;
//#endif
//        }
}
