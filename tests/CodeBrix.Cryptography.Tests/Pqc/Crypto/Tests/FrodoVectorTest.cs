using System.Collections.Generic;
using System.Linq;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Pqc.Crypto.Frodo;
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
public class FrodoVectorTest
{
    private static readonly Dictionary<string, FrodoParameters> Parameters = new Dictionary<string, FrodoParameters>()
    {
        { "PQCkemKAT_19888.rsp", FrodoParameters.frodokem640aes },
        { "PQCkemKAT_31296.rsp", FrodoParameters.frodokem976aes },
        { "PQCkemKAT_43088.rsp", FrodoParameters.frodokem1344aes },
        { "PQCkemKAT_19888_shake.rsp", FrodoParameters.frodokem640shake },
        { "PQCkemKAT_31296_shake.rsp", FrodoParameters.frodokem976shake },
        { "PQCkemKAT_43088_shake.rsp", FrodoParameters.frodokem1344shake },
    };

    public static IEnumerable<object[]> TestVectorFilesAes_Data => TestVectorFilesAes.Select(v => new object[] { v });

    private static readonly string[] TestVectorFilesAes =
    {
        "PQCkemKAT_19888.rsp",
        "PQCkemKAT_31296.rsp",
        "PQCkemKAT_43088.rsp",
    };

    public static IEnumerable<object[]> TestVectorFilesShake_Data => TestVectorFilesShake.Select(v => new object[] { v });

    private static readonly string[] TestVectorFilesShake =
    {
        "PQCkemKAT_19888_shake.rsp",
        "PQCkemKAT_31296_shake.rsp",
        "PQCkemKAT_43088_shake.rsp",
    };

    [Fact]
    public void TestParameters()
    {
        Assert.Equal(128, FrodoParameters.frodokem640aes.DefaultKeySize);
        Assert.Equal(128, FrodoParameters.frodokem640shake.DefaultKeySize);
        Assert.Equal(192, FrodoParameters.frodokem976aes.DefaultKeySize);
        Assert.Equal(192, FrodoParameters.frodokem976shake.DefaultKeySize);
        Assert.Equal(256, FrodoParameters.frodokem1344aes.DefaultKeySize);
        Assert.Equal(256, FrodoParameters.frodokem1344shake.DefaultKeySize);
    }

    [Theory(Skip = BcTestData.SkipReason, SkipUnless = nameof(BcTestData.IsAvailable), SkipType = typeof(BcTestData))]
    [MemberData(nameof(TestVectorFilesAes_Data))]
    public void TVAes(string testVectorFile) =>
        PqcTestUtilities.RunTestVectors("pqc/crypto/frodo", testVectorFile, sampleOnly: true, RunTestVector);

    [Theory(Skip = BcTestData.SkipReason, SkipUnless = nameof(BcTestData.IsAvailable), SkipType = typeof(BcTestData))]
    [MemberData(nameof(TestVectorFilesShake_Data))]
    public void TVShake(string testVectorFile) =>
        PqcTestUtilities.RunTestVectors("pqc/crypto/frodo", testVectorFile, sampleOnly: true, RunTestVector);

    private static void RunTestVector(string path, Dictionary<string, string> data)
    {
        string count = data["count"];
        byte[] seed = Hex.Decode(data["seed"]); // seed for SecureRandom
        byte[] pk = Hex.Decode(data["pk"]);     // public key
        byte[] sk = Hex.Decode(data["sk"]);     // private key
        byte[] ct = Hex.Decode(data["ct"]);     // ciphertext
        byte[] ss = Hex.Decode(data["ss"]);     // session key

        NistSecureRandom random = new NistSecureRandom(seed, null);
        FrodoParameters frodoParameters = Parameters[path];

        FrodoKeyPairGenerator kpGen = new FrodoKeyPairGenerator();
        FrodoKeyGenerationParameters genParams = new FrodoKeyGenerationParameters(random, frodoParameters);
        //
        // Generate keys and test.
        //
        kpGen.Init(genParams);
        AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

        FrodoPublicKeyParameters pubParams = (FrodoPublicKeyParameters)PqcPublicKeyFactory.CreateKey(
            PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((FrodoPublicKeyParameters)kp.Public));
        FrodoPrivateKeyParameters privParams = (FrodoPrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(
            PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo((FrodoPrivateKeyParameters)kp.Private));

        Assert.True(Arrays.AreEqual(pk, pubParams.GetPublicKey()), $"{path} {count} : public key");
        Assert.True(Arrays.AreEqual(sk, privParams.GetPrivateKey()), $"{path} {count} : secret key");

        // kem_enc
        FrodoKEMGenerator frodoEncCipher = new FrodoKEMGenerator(random);
        ISecretWithEncapsulation secWenc = frodoEncCipher.GenerateEncapsulated(pubParams);
        byte[] generated_cipher_text = secWenc.GetEncapsulation();
        Assert.True(Arrays.AreEqual(ct, generated_cipher_text), path + " " + count + ": kem_enc cipher text");
        byte[] secret = secWenc.GetSecret();
        Assert.True(Arrays.AreEqual(ss, secret), path + " " + count + ": kem_enc key");

        // kem_dec
        FrodoKEMExtractor frodoDecCipher = new FrodoKEMExtractor(privParams);

        byte[] dec_key = frodoDecCipher.ExtractSecret(generated_cipher_text);

        Assert.True(frodoParameters.DefaultKeySize == dec_key.Length * 8);
        Assert.True(Arrays.AreEqual(dec_key, ss), $"{path} {count}: kem_dec ss");
        Assert.True(Arrays.AreEqual(dec_key, secret), $"{path} {count}: kem_dec key");
    }
}
