using System.Collections.Generic;
using System.Linq;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Pqc.Crypto.Bike;
using CodeBrix.Cryptography.Pqc.Crypto.Utilities;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Pqc.Crypto.Tests; //was previously: Org.BouncyCastle.Pqc.Crypto.Tests;

/// <remarks>
/// The fixtures these tests read live only in BouncyCastle's external bc-test-data
/// repository, which carries no licence and so cannot be redistributed here. They are
/// skipped unless that repository is cloned as a SIBLING of CodeBrix.Cryptography and
/// CODEBRIX_CRYPTOGRAPHY_USE_BC_TEST_DATA=1 is set. See BcTestData.
/// </remarks>
public class BikeVectorTest
{
    private static readonly Dictionary<string, BikeParameters> Parameters = new Dictionary<string, BikeParameters>()
    {
        { "PQCkemKAT_BIKE_3114.rsp", BikeParameters.bike128 },
        { "PQCkemKAT_BIKE_6198.rsp", BikeParameters.bike192 },
        { "PQCkemKAT_BIKE_10276.rsp", BikeParameters.bike256 },
    };

    public static IEnumerable<object[]> TestVectorFiles_Data => TestVectorFiles.Select(v => new object[] { v });

    private static readonly IEnumerable<string> TestVectorFiles = Parameters.Keys;

    [Fact]
    public void TestParameters()
    {
        Assert.Equal(128, BikeParameters.bike128.DefaultKeySize);
        Assert.Equal(192, BikeParameters.bike192.DefaultKeySize);
        Assert.Equal(256, BikeParameters.bike256.DefaultKeySize);
    }

    [Fact]
    public void TestDecodingFailureImplicitRejection()
    {
        // A ciphertext that fails to decode must be handled by Fujisaki-Okamoto implicit rejection
        // (returning a pseudo-random shared secret), not by throwing. The decoder previously returned
        // null on a decoding failure, which surfaced as a NullReferenceException out of decapsulation
        // -- an uncaught crash on malformed input and a decryption-failure oracle.
        byte[] seed = new byte[48];
        for (int i = 0; i != seed.Length; i++)
        {
            seed[i] = (byte)i;
        }

        NistSecureRandom random = new NistSecureRandom(seed, null);
        BikeParameters parameters = BikeParameters.bike128;

        BikeKeyPairGenerator kpGen = new BikeKeyPairGenerator();
        kpGen.Init(new BikeKeyGenerationParameters(random, parameters));
        AsymmetricCipherKeyPair pair = kpGen.GenerateKeyPair();

        BikeKemGenerator kemGen = new BikeKemGenerator(random);
        ISecretWithEncapsulation enc = kemGen.GenerateEncapsulated((BikePublicKeyParameters)pair.Public);
        byte[] goodSecret = enc.GetSecret();

        // Corrupt a prefix of c0 (well within the syndrome region, away from the high-bit padding
        // byte that DecodeBytes validates) with far more than t bit-flips, forcing a guaranteed
        // decoding failure on a still-well-formed ciphertext. ExtractSecret must still return a
        // session key of the correct length rather than throwing, and a different one.
        byte[] badCt = (byte[])enc.GetEncapsulation().Clone();
        for (int i = 0; i < 256; i++)
        {
            badCt[i] ^= 0xFF;
        }

        BikeKemExtractor extractor = new BikeKemExtractor((BikePrivateKeyParameters)pair.Private);
        byte[] rejectKey = extractor.ExtractSecret(badCt);

        Assert.NotNull(rejectKey);
        Assert.Equal(parameters.DefaultKeySize / 8, rejectKey.Length);
        Assert.False(Arrays.AreEqual(rejectKey, goodSecret), "implicit rejection key must differ from the genuine shared secret");
    }

    [Theory(Skip = BcTestData.SkipReason, SkipUnless = nameof(BcTestData.IsAvailable), SkipType = typeof(BcTestData))]
    [MemberData(nameof(TestVectorFiles_Data))]
    public void TV(string testVectorFile) =>
        PqcTestUtilities.RunTestVectors("pqc/crypto/bike", testVectorFile, sampleOnly: false, RunTestVector);

    private static void RunTestVector(string path, Dictionary<string, string> data)
    {
        string count = data["count"];
        byte[] seed = Hex.Decode(data["seed"]); // seed for SecureRandom
        byte[] pk = Hex.Decode(data["pk"]);     // public key
        byte[] sk = Hex.Decode(data["sk"]);     // private key
        byte[] ct = Hex.Decode(data["ct"]);     // ciphertext
        byte[] ss = Hex.Decode(data["ss"]);     // session key

        NistSecureRandom random = new NistSecureRandom(seed, null);
        BikeParameters bikeParameters = Parameters[path];

        BikeKeyPairGenerator kpGen = new BikeKeyPairGenerator();
        BikeKeyGenerationParameters genParam = new BikeKeyGenerationParameters(random, bikeParameters);
        //
        // Generate keys and test.
        //
        kpGen.Init(genParam);
        AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

        BikePublicKeyParameters pubParams = (BikePublicKeyParameters)PqcPublicKeyFactory.CreateKey(
            PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((BikePublicKeyParameters) kp.Public));
        BikePrivateKeyParameters privParams = (BikePrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(
            PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo((BikePrivateKeyParameters) kp.Private));

        Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), path + " " + count + ": public key");
        Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), path + " " + count + ": secret key");

        // KEM Enc
        BikeKemGenerator BikeEncCipher = new BikeKemGenerator(random);
        ISecretWithEncapsulation secWenc = BikeEncCipher.GenerateEncapsulated(pubParams);
        byte[] generated_cipher_text = secWenc.GetEncapsulation();
        Assert.True(Arrays.AreEqual(ct, generated_cipher_text), path + " " + count + ": kem_enc cipher text");

        byte[] secret = secWenc.GetSecret();
        Assert.True(Arrays.AreEqual(ss, 0, secret.Length, secret, 0, secret.Length), path + " " + count + ": kem_enc key");

        // KEM Dec
        BikeKemExtractor BikeDecCipher = new BikeKemExtractor(privParams);

        byte[] dec_key = BikeDecCipher.ExtractSecret(generated_cipher_text);

        Assert.True(bikeParameters.DefaultKeySize == dec_key.Length * 8);
        Assert.True(Arrays.AreEqual(dec_key, 0, dec_key.Length, ss, 0, dec_key.Length), path + " " + count + ": kem_dec ss");
        Assert.True(Arrays.AreEqual(dec_key, secret), path + " " + count + ": kem_dec key");
    }
}
