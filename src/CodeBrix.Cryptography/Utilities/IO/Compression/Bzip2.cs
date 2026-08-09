using System.IO;
using Impl = CodeBrix.Cryptography.Utilities.Bzip2;

namespace CodeBrix.Cryptography.Utilities.IO.Compression; //was previously: Org.BouncyCastle.Utilities.IO.Compression;

internal static class Bzip2
{
    internal static Stream CompressOutput(Stream stream, bool leaveOpen = false)
    {
        return leaveOpen
            ?   new Impl.CBZip2OutputStreamLeaveOpen(stream)
            :   new Impl.CBZip2OutputStream(stream);
    }

    internal static Stream DecompressInput(Stream stream, bool leaveOpen = false)
    {
        return leaveOpen
            ?   new Impl.CBZip2InputStreamLeaveOpen(stream)
            :   new Impl.CBZip2InputStream(stream);
    }
}
