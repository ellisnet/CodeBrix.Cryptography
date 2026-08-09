using System;
using System.IO;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Cmp;
using CodeBrix.Cryptography.Asn1.Pkcs;
using CodeBrix.Cryptography.Cms;
using CodeBrix.Cryptography.X509;

namespace CodeBrix.Cryptography.Cmp; //was previously: Org.BouncyCastle.Cmp;

/// <summary>Carrier class for a <see cref="CmpCertificate"/> over CMS.</summary>
public sealed class CmsProcessableCmpCertificate
    : CmsTypedData
{
    private readonly CmpCertificate m_cmpCertificate;

    public CmsProcessableCmpCertificate(X509Certificate certificate)
        : this(new CmpCertificate(certificate.CertificateStructure))
    {
    }

    public CmsProcessableCmpCertificate(CmpCertificate cmpCertificate)
    {
        m_cmpCertificate = cmpCertificate ?? throw new ArgumentNullException(nameof(cmpCertificate));
    }

    public void Write(Stream outStream)
    {
        m_cmpCertificate.EncodeTo(outStream);
    }

    public DerObjectIdentifier ContentType => PkcsObjectIdentifiers.Data;
}
