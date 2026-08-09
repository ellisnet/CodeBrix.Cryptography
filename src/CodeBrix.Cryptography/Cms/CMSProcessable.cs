using System;
using System.IO;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

public interface CmsProcessable
{
    /// <summary>
    /// Generic routine to copy out the data we want processed.
    /// </summary>
    /// <remarks>
    /// This routine may be called multiple times.
    /// </remarks>
    void Write(Stream outStream);
}
