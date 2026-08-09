using System;

namespace CodeBrix.Cryptography.Tls; //was previously: Org.BouncyCastle.Tls;

/// <summary>Marker interface to distinguish a TLS server context.</summary>
public interface TlsServerContext
    : TlsContext
{
}
