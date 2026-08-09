using CodeBrix.Cryptography.Asn1.Nist;
using CodeBrix.Cryptography.Asn1.Pkcs;
using CodeBrix.Cryptography.Crypto.Agreement.Kdf;
using CodeBrix.Cryptography.Crypto.Digests;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Encoders;
using Xunit;

namespace CodeBrix.Cryptography.Crypto.Tests; //was previously: Org.BouncyCastle.Crypto.Tests;

/// <remarks>ECDHKEK Generator tests.</remarks>
public class ECDHKekGeneratorTest
{
    private readonly SecureRandom Random = new SecureRandom();

    [Fact]
    public void Test128()
    {
        byte[] seed = Hex.Decode("75d7487b5d3d2bfb3c69ce0365fe64e3bfab5d0d63731628a9f47eb8fddfa28c65decaf228a0b38f0c51c6a3356d7c56");
        byte[] result = Hex.Decode("042be1faca3a4a8fc859241bfb87ba35");

        var kdf = new ECDHKekGenerator(new Sha1Digest());
        var kdfParameters = new DHKdfParameters(NistObjectIdentifiers.IdAes128Wrap, 128, seed);

        CheckMask(nameof(Test128), kdf, kdfParameters, result);
    }

    [Fact]
    public void Test192()
    {
        byte[] seed = Hex.Decode("fdeb6d809f997e8ac174d638734dc36d37aaf7e876e39967cd82b1cada3de772449788461ee7f856bad9305627f8e48b");
        byte[] result = Hex.Decode("bcd701fc92109b1b9d6f3b6497ad5ca9627fa8a597010305");

        var kdf = new ECDHKekGenerator(new Sha1Digest());
        var kdfParameters = new DHKdfParameters(PkcsObjectIdentifiers.IdAlgCms3DesWrap, 192, seed);

        CheckMask(nameof(Test192), kdf, kdfParameters, result);
    }

    [Fact]
    public void Test256()
    {
        byte[] seed = Hex.Decode("db4a8daba1f98791d54e940175dd1a5f3a0826a1066aa9b668d4dc1e1e0790158dcad1533c03b44214d1b61fefa8b579");
        byte[] result = Hex.Decode("8ecc6d85caf25eaba823a7d620d4ab0d33e4c645f2");

        var kdf = new ECDHKekGenerator(new Sha1Digest());
        var kdfParameters = new DHKdfParameters(NistObjectIdentifiers.IdAes256Wrap, 256, seed);

        CheckMask(nameof(Test256), kdf, kdfParameters, result);
    }

    private void CheckMask(string name, IDerivationFunction kdf, IDerivationParameters parameters, byte[] result)
    {
        byte[] data = SecureRandom.GetNextBytes(Random, result.Length);

        kdf.Init(parameters);
        kdf.GenerateBytes(data, 0, data.Length);

        Assert.True(Arrays.AreEqual(result, data), "ECDHKekGenerator failed generator test " + name);
    }
}
