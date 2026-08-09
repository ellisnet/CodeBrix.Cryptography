using System.Collections.Generic;
using System.Linq;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Pqc.Crypto.Cmce;
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
public class CmceVectorTest
{
    private static readonly Dictionary<string, CmceParameters> Parameters = new Dictionary<string, CmceParameters>()
    {
        { "3488-64-cmce.rsp", CmceParameters.mceliece348864r3 },
        { "3488-64-f-cmce.rsp", CmceParameters.mceliece348864fr3 },
        { "4608-96-cmce.rsp", CmceParameters.mceliece460896r3 },
        { "4608-96-f-cmce.rsp", CmceParameters.mceliece460896fr3 },
        { "6688-128-cmce.rsp", CmceParameters.mceliece6688128r3 },
        { "6688-128-f-cmce.rsp", CmceParameters.mceliece6688128fr3 },
        { "6960-119-cmce.rsp", CmceParameters.mceliece6960119r3 },
        { "6960-119-f-cmce.rsp", CmceParameters.mceliece6960119fr3 },
        { "8192-128-cmce.rsp", CmceParameters.mceliece8192128r3 },
        { "8192-128-f-cmce.rsp", CmceParameters.mceliece8192128fr3 },
    };

    public static IEnumerable<object[]> TestVectorFiles_Data => TestVectorFiles.Select(v => new object[] { v });

    private static readonly string[] TestVectorFiles =
    {
        "3488-64-cmce.rsp",
        "4608-96-cmce.rsp",
        "6688-128-cmce.rsp",
        "6960-119-cmce.rsp",
        "8192-128-cmce.rsp",
    };

    public static IEnumerable<object[]> TestVectorFilesFast_Data => TestVectorFilesFast.Select(v => new object[] { v });

    private static readonly string[] TestVectorFilesFast =
    {
        "3488-64-f-cmce.rsp",
        "4608-96-f-cmce.rsp",
        "6688-128-f-cmce.rsp",
        "6960-119-f-cmce.rsp",
        "8192-128-f-cmce.rsp",
    };

    [Fact]
    public void TestParameters()
    {
        Assert.Equal(128, CmceParameters.mceliece348864r3.DefaultKeySize);
        Assert.Equal(128, CmceParameters.mceliece348864fr3.DefaultKeySize);
        Assert.Equal(192, CmceParameters.mceliece460896r3.DefaultKeySize);
        Assert.Equal(192, CmceParameters.mceliece460896fr3.DefaultKeySize);
        Assert.Equal(256, CmceParameters.mceliece6688128r3.DefaultKeySize);
        Assert.Equal(256, CmceParameters.mceliece6688128fr3.DefaultKeySize);
        Assert.Equal(256, CmceParameters.mceliece6960119r3.DefaultKeySize);
        Assert.Equal(256, CmceParameters.mceliece6960119fr3.DefaultKeySize);
        Assert.Equal(256, CmceParameters.mceliece8192128r3.DefaultKeySize);
        Assert.Equal(256, CmceParameters.mceliece8192128fr3.DefaultKeySize);
    }

    [Theory(Skip = BcTestData.SkipReason, SkipUnless = nameof(BcTestData.IsAvailable), SkipType = typeof(BcTestData))]
    [MemberData(nameof(TestVectorFiles_Data))]
    public void TV(string testVectorFile) =>
        PqcTestUtilities.RunTestVectors("pqc/crypto/cmce", testVectorFile, sampleOnly: true, RunTestVector);

    [Theory(Skip = BcTestData.SkipReason, SkipUnless = nameof(BcTestData.IsAvailable), SkipType = typeof(BcTestData))]
    [MemberData(nameof(TestVectorFilesFast_Data))]
    public void TVFast(string testVectorFile) =>
        PqcTestUtilities.RunTestVectors("pqc/crypto/cmce", testVectorFile, sampleOnly: true, RunTestVector);

    private static void RunTestVector(string path, Dictionary<string, string> data)
    {
        string count = data["count"];
        byte[] seed = Hex.Decode(data["seed"]); // seed for SecureRandom
        byte[] pk = Hex.Decode(data["pk"]);     // public key
        byte[] sk = Hex.Decode(data["sk"]);     // private key
        byte[] ct = Hex.Decode(data["ct"]);     // ciphertext
        byte[] ss = Hex.Decode(data["ss"]);     // session key

        NistSecureRandom random = new NistSecureRandom(seed, null);
        CmceParameters Cmceparameters = Parameters[path];

        CmceKeyPairGenerator kpGen = new CmceKeyPairGenerator();
        CmceKeyGenerationParameters genParam = new CmceKeyGenerationParameters(random, Cmceparameters);
        //
        // Generate keys and test.
        //
        kpGen.Init(genParam);
        AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

        CmcePublicKeyParameters pubParams = (CmcePublicKeyParameters)PqcPublicKeyFactory.CreateKey(
            PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((CmcePublicKeyParameters)kp.Public));
        CmcePrivateKeyParameters privParams = (CmcePrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(
            PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo((CmcePrivateKeyParameters)kp.Private));

        Assert.True(Arrays.AreEqual(pk, pubParams.GetPublicKey()), path + " " + count + ": public key");
        Assert.True(Arrays.AreEqual(sk, privParams.GetPrivateKey()), path + " " + count + ": secret key");

        // KEM Enc
        CmceKemGenerator CmceEncCipher = new CmceKemGenerator(random);
        ISecretWithEncapsulation secWenc = CmceEncCipher.GenerateEncapsulated(pubParams);
        byte[] generated_cipher_text = secWenc.GetEncapsulation();
        Assert.True(Arrays.AreEqual(ct, generated_cipher_text), path + " " + count + ": kem_enc cipher text");
        byte[] secret = secWenc.GetSecret();
        Assert.True(Arrays.AreEqual(ss, 0, secret.Length, secret, 0, secret.Length), path + " " + count + ": kem_enc key");

        // KEM Dec
        CmceKemExtractor CmceDecCipher = new CmceKemExtractor(privParams);

        byte[] dec_key = CmceDecCipher.ExtractSecret(generated_cipher_text);

        Assert.True(Cmceparameters.DefaultKeySize == dec_key.Length * 8);
        Assert.True(Arrays.AreEqual(dec_key, 0, dec_key.Length, ss, 0, dec_key.Length), path + " " + count + ": kem_dec ss");
        Assert.True(Arrays.AreEqual(dec_key, secret), path + " " + count + ": kem_dec key");
    }
}
