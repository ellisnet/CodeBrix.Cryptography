using System;
using CodeBrix.Cryptography.Asn1.Cmp;
using CodeBrix.Cryptography.Asn1.Crmf;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.X509;

namespace CodeBrix.Cryptography.Crmf; //was previously: Org.BouncyCastle.Crmf;

internal class PKMacValueVerifier
{
    private readonly PKMacBuilder m_builder;

    internal PKMacValueVerifier(PKMacBuilder builder)
    {
        m_builder = builder;
    }

    internal virtual bool IsValid(PKMacValue value, ReadOnlySpan<char> password, SubjectPublicKeyInfo keyInfo)
    {
        m_builder.SetParameters(PbmParameter.GetInstance(value.AlgID.Parameters));

        var macFactory = m_builder.Build(password);

        return X509Utilities.VerifyMac(macFactory, keyInfo, value.MacValue);
    }
}
