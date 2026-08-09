using System;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Cmp;
using CodeBrix.Cryptography.Asn1.Crmf;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Math;
using CodeBrix.Cryptography.X509;

namespace CodeBrix.Cryptography.Cmp; //was previously: Org.BouncyCastle.Cmp;

public sealed class RevocationDetailsBuilder
{
    private readonly CertTemplateBuilder m_templateBuilder = new CertTemplateBuilder();

    public RevocationDetailsBuilder SetPublicKey(AsymmetricKeyParameter publicKey) =>
        SetSubjectPublicKeyInfo(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey));

    [Obsolete("Use 'SetSubjectPublicKeyInfo' instead")]
    public RevocationDetailsBuilder SetPublicKey(SubjectPublicKeyInfo publicKey) =>
        SetSubjectPublicKeyInfo(spki: publicKey);

    public RevocationDetailsBuilder SetSubjectPublicKeyInfo(SubjectPublicKeyInfo spki)
    {
        if (spki != null)
        {
            m_templateBuilder.SetSubjectPublicKeyInfo(spki);
        }

        return this;
    }

    public RevocationDetailsBuilder SetIssuer(X509Name issuer)
    {
        if (issuer != null)
        {
            m_templateBuilder.SetIssuer(issuer);
        }

        return this;
    }

    public RevocationDetailsBuilder SetSerialNumber(BigInteger serialNumber)
    {
        if (serialNumber != null)
        {
            m_templateBuilder.SetSerialNumber(new DerInteger(serialNumber));
        }

        return this;
    }

    public RevocationDetailsBuilder SetSubject(X509Name subject)
    {
        if (subject != null)
        {
            m_templateBuilder.SetSubject(subject);
        }

        return this;
    }

    public RevocationDetails Build()
    {
        return new RevocationDetails(new RevDetails(m_templateBuilder.Build()));
    }
}
