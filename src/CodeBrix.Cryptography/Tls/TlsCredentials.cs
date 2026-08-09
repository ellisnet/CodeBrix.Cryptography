using System;

namespace CodeBrix.Cryptography.Tls; //was previously: Org.BouncyCastle.Tls;

/// <summary>Base interface for interfaces/classes carrying TLS credentials.</summary>
public interface TlsCredentials
{
    /// <summary>Return the certificate structure representing our identity.</summary>
    /// <returns>our certificate structure.</returns>
	Certificate Certificate { get; }
}
