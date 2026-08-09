using System;
using System.IO;

namespace CodeBrix.Cryptography.Tls.Crypto; //was previously: Org.BouncyCastle.Tls.Crypto;

public interface TlsStreamSigner
{
    /// <exception cref="IOException"/>
    Stream Stream { get; }

    /// <exception cref="IOException"/>
    byte[] GetSignature();
}
