using System;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Cms;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Cms;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.X509;

namespace CodeBrix.Cryptography.Operators; //was previously: Org.BouncyCastle.Operators;

/// <deprecated>Use KeyTransRecipientInfoGenerator</deprecated>
public class CmsKeyTransRecipientInfoGenerator
    : KeyTransRecipientInfoGenerator
{
    public CmsKeyTransRecipientInfoGenerator(X509Certificate recipCert, IKeyWrapper keyWrapper)
        : base(new Asn1.Cms.IssuerAndSerialNumber(recipCert.CertificateStructure), keyWrapper)
    {
    }

    public CmsKeyTransRecipientInfoGenerator(IssuerAndSerialNumber issuerAndSerial, IKeyWrapper keyWrapper)
        : base(issuerAndSerial, keyWrapper)
    {
    }

    public CmsKeyTransRecipientInfoGenerator(byte[] subjectKeyID, IKeyWrapper keyWrapper) : base(subjectKeyID, keyWrapper)
    {
    }
}
