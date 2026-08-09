using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Ocsp;
using CodeBrix.Cryptography.X509;
using CodeBrix.Cryptography.X509.Extension;

namespace CodeBrix.Cryptography.Ocsp; //was previously: Org.BouncyCastle.Ocsp;

public static class OcspUtilities
{
    public static Asn1OctetString GetNonce(IX509Extension extension) =>
        extension.GetExtension(OcspObjectIdentifiers.PkixOcspNonce, Asn1OctetString.GetInstance);
}
