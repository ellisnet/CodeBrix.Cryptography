using System.Collections.Generic;
using System.Linq;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Pqc.Crypto.Saber;
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
public class SaberVectorTest
{
    private static readonly Dictionary<string, SaberParameters> Parameters = new Dictionary<string, SaberParameters>()
    {
        { "lightsaber.rsp", SaberParameters.lightsaberkem256r3 },
        { "saber.rsp", SaberParameters.saberkem256r3 },
        { "firesaber.rsp", SaberParameters.firesaberkem256r3 },

        { "ulightsaber.rsp", SaberParameters.ulightsaberkemr3},
        { "usaber.rsp", SaberParameters.usaberkemr3},
        { "ufiresaber.rsp", SaberParameters.ufiresaberkemr3},

        { "lightsaber-90s.rsp", SaberParameters.lightsaberkem90sr3},
        { "saber-90s.rsp", SaberParameters.saberkem90sr3},
        { "firesaber-90s.rsp", SaberParameters.firesaberkem90sr3},

        { "ulightsaber-90s.rsp", SaberParameters.ulightsaberkem90sr3},
        { "usaber-90s.rsp", SaberParameters.usaberkem90sr3},
        { "ufiresaber-90s.rsp", SaberParameters.ufiresaberkem90sr3},
    };

    public static IEnumerable<object[]> TestVectorFiles_Data => TestVectorFiles.Select(v => new object[] { v });

    private static readonly IEnumerable<string> TestVectorFiles = Parameters.Keys;

    [Fact]
    public void TestParameters()
    {
        Assert.Equal(128, SaberParameters.lightsaberkem128r3.DefaultKeySize);
        Assert.Equal(128, SaberParameters.saberkem128r3.DefaultKeySize);
        Assert.Equal(128, SaberParameters.firesaberkem128r3.DefaultKeySize);
        Assert.Equal(192, SaberParameters.lightsaberkem192r3.DefaultKeySize);
        Assert.Equal(192, SaberParameters.saberkem192r3.DefaultKeySize);
        Assert.Equal(192, SaberParameters.firesaberkem192r3.DefaultKeySize);
        Assert.Equal(256, SaberParameters.lightsaberkem256r3.DefaultKeySize);
        Assert.Equal(256, SaberParameters.saberkem256r3.DefaultKeySize);
        Assert.Equal(256, SaberParameters.firesaberkem256r3.DefaultKeySize);
    }

    [Theory(Skip = BcTestData.SkipReason, SkipUnless = nameof(BcTestData.IsAvailable), SkipType = typeof(BcTestData))]
    [MemberData(nameof(TestVectorFiles_Data))]
    public void TV(string testVectorFile) =>
        PqcTestUtilities.RunTestVectors("pqc/crypto/saber", testVectorFile, sampleOnly: true, RunTestVector);

    private static void RunTestVector(string path, Dictionary<string, string> data)
    {
        string count = data["count"];
        byte[] seed = Hex.Decode(data["seed"]); // seed for SecureRandom
        byte[] pk = Hex.Decode(data["pk"]); // public key
        byte[] sk = Hex.Decode(data["sk"]); // private key
        byte[] ct = Hex.Decode(data["ct"]); // ciphertext
        byte[] ss = Hex.Decode(data["ss"]); // session key

        NistSecureRandom random = new NistSecureRandom(seed, null);
        SaberParameters parameters = Parameters[path];

        SaberKeyPairGenerator kpGen = new SaberKeyPairGenerator();
        SaberKeyGenerationParameters genParam = new SaberKeyGenerationParameters(random, parameters);
        //
        // Generate keys and test.
        //
        kpGen.Init(genParam);
        AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

        SaberPublicKeyParameters pubParams = (SaberPublicKeyParameters)PqcPublicKeyFactory.CreateKey(
            PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((SaberPublicKeyParameters)kp.Public));
        SaberPrivateKeyParameters privParams = (SaberPrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(
            PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo((SaberPrivateKeyParameters)kp.Private));

        Assert.True(Arrays.AreEqual(pk, pubParams.GetPublicKey()), path + " " + count + ": public key");
        Assert.True(Arrays.AreEqual(sk, privParams.GetPrivateKey()), path + " " + count + ": secret key");

        // KEM Enc
        SaberKemGenerator SABEREncCipher = new SaberKemGenerator(random);
        ISecretWithEncapsulation secWenc = SABEREncCipher.GenerateEncapsulated(pubParams);
        byte[] generated_cipher_text = secWenc.GetEncapsulation();
        Assert.True(Arrays.AreEqual(ct, generated_cipher_text), path + " " + count + ": kem_enc cipher text");
        byte[] secret = secWenc.GetSecret();
        Assert.True(Arrays.AreEqual(ss, 0, secret.Length, secret, 0, secret.Length), path + " " + count + ": kem_enc key");

        // KEM Dec
        SaberKemExtractor SABERDecCipher = new SaberKemExtractor(privParams);

        byte[] dec_key = SABERDecCipher.ExtractSecret(generated_cipher_text);

        Assert.True(parameters.DefaultKeySize == dec_key.Length * 8);
        Assert.True(Arrays.AreEqual(dec_key, 0, dec_key.Length, ss, 0, dec_key.Length), path + " " + count + ": kem_dec ss");
        Assert.True(Arrays.AreEqual(dec_key, secret), path + " " + count + ": kem_dec key");
    }
}
