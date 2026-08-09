using System;
using System.IO;

namespace CodeBrix.Cryptography.Tls; //was previously: Org.BouncyCastle.Tls;

public interface TlsCloseable
{
    /// <exception cref="IOException"/>
    void Close();
}
