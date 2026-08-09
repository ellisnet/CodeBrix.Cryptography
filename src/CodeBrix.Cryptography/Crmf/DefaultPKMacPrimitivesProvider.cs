using System;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Crmf; //was previously: Org.BouncyCastle.Crmf;

public class DefaultPKMacPrimitivesProvider
    : IPKMacPrimitivesProvider
{
    public IDigest CreateDigest(AlgorithmIdentifier digestAlg)
    {
        return DigestUtilities.GetDigest(digestAlg.Algorithm);
    }

    public IMac CreateMac(AlgorithmIdentifier macAlg)
    {
        return MacUtilities.GetMac(macAlg.Algorithm);
    }
}
