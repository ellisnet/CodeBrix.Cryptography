using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Crypto.Agreement.Kdf;
using CodeBrix.Cryptography.Math;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities;

namespace CodeBrix.Cryptography.Crypto.Agreement; //was previously: Org.BouncyCastle.Crypto.Agreement;

internal static class BasicAgreementWithKdf
{
    internal static BigInteger CalculateAgreementWithKdf(string algorithm, IDerivationFunction kdf, int fieldSize,
        BigInteger result)
    {
        // Note that the ec.KeyAgreement class in JCE only uses kdf in oneof the engineGenerateSecret methods.

        int keySize = GeneratorUtilities.GetDefaultKeySize(algorithm);

        DHKdfParameters dhKdfParams = new DHKdfParameters(
            new DerObjectIdentifier(algorithm),
            keySize,
            BigIntegers.AsUnsignedByteArray(fieldSize, result));

        kdf.Init(dhKdfParams);

        byte[] keyBytes = new byte[keySize / 8];
        kdf.GenerateBytes(keyBytes, 0, keyBytes.Length);

        return new BigInteger(1, keyBytes);
    }
}
