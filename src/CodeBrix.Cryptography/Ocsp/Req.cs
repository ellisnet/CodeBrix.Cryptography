using System;
using CodeBrix.Cryptography.Asn1.Ocsp;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.X509;

namespace CodeBrix.Cryptography.Ocsp; //was previously: Org.BouncyCastle.Ocsp;

public class Req
    : X509ExtensionBase
{
    private readonly Request m_req;

    public Req(Request req)
    {
        m_req = req ?? throw new ArgumentNullException(nameof(req));
    }

    public CertificateID GetCertID() => new CertificateID(m_req.ReqCert);

    public X509Extensions SingleRequestExtensions => m_req.SingleRequestExtensions;

    protected override X509Extensions GetX509Extensions() => SingleRequestExtensions;
}
