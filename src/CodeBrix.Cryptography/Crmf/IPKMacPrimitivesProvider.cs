using System;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Crypto;

namespace CodeBrix.Cryptography.Crmf; //was previously: Org.BouncyCastle.Crmf;

public interface IPKMacPrimitivesProvider
{
    IDigest CreateDigest(AlgorithmIdentifier digestAlg);

    IMac CreateMac(AlgorithmIdentifier macAlg);
}
