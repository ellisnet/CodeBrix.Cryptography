using System;

namespace CodeBrix.Cryptography.Tls; //was previously: Org.BouncyCastle.Tls;

/// <summary>Server certificate carrier interface.</summary>
public interface TlsServerCertificate
{
    Certificate Certificate { get; }

    CertificateStatus CertificateStatus { get; }
}
