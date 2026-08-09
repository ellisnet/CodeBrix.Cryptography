using System;
using CodeBrix.Cryptography.Tls.Crypto;

namespace CodeBrix.Cryptography.Tls; //was previously: Org.BouncyCastle.Tls;

public interface TlsPsk
{
    byte[] Identity { get; }

    TlsSecret Key { get; }

    int PrfAlgorithm { get; }
}
