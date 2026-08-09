using System;
using CodeBrix.Cryptography.Asn1.Crmf;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.X509;

namespace CodeBrix.Cryptography.Crmf; //was previously: Org.BouncyCastle.Crmf;

internal static class PKMacValueGenerator
{
    internal static PKMacValue Generate(PKMacBuilder builder, ReadOnlySpan<char> password,
        SubjectPublicKeyInfo keyInfo)
    {
        var macFactory = builder.Build(password);
        var macValue = X509Utilities.GenerateMac(macFactory, keyInfo);
        return new PKMacValue((AlgorithmIdentifier)macFactory.AlgorithmDetails, macValue);
    }
}
