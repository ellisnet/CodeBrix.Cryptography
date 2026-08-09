using System;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Crypto;

namespace CodeBrix.Cryptography.X509.Extension; //was previously: Org.BouncyCastle.X509.Extension;

/// <summary>A high level subject key identifier.</summary>
[Obsolete("Use 'X509ExtensionUtilities' methods instead")]
public class SubjectKeyIdentifierStructure
    : SubjectKeyIdentifier
{
    public SubjectKeyIdentifierStructure(Asn1OctetString encodedValue)
        : base(Asn1OctetString.GetInstance(encodedValue.GetOctets()))
    {
    }

    public SubjectKeyIdentifierStructure(AsymmetricKeyParameter pubKey)
        : base(keyID: X509ExtensionUtilities.CalculateKeyIdentifier(pubKey))
    {
    }
}
