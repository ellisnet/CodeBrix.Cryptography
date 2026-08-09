using System;

namespace CodeBrix.Cryptography.Tls; //was previously: Org.BouncyCastle.Tls;

/// <summary>Marker interface to distinguish a TLS client context.</summary>
public interface TlsClientContext
    : TlsContext
{
}
