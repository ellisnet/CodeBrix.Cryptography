using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Operators.Utilities;

namespace CodeBrix.Cryptography.Cmp; //was previously: Org.BouncyCastle.Cmp;

internal static class CmpUtilities
{
    internal static byte[] CalculateCertHash(Asn1Encodable asn1Encodable, AlgorithmIdentifier signatureAlgorithm,
        IDigestAlgorithmFinder digestAlgorithmFinder)
    {
        var digestAlgorithm = digestAlgorithmFinder.Find(signatureAlgorithm)
            ?? throw new CmpException("cannot find digest algorithm from signature algorithm");

        return X509.X509Utilities.CalculateDigest(digestAlgorithm, asn1Encodable);
    }
}
