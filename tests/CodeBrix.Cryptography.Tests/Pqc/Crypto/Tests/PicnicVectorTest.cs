using System.Collections.Generic;
using System.Linq;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Pqc.Crypto.Picnic;
using CodeBrix.Cryptography.Pqc.Crypto.Utilities;
using CodeBrix.Cryptography.Security;
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
public class PicnicVectorTest
{
    private static readonly Dictionary<string, PicnicParameters> Parameters = new Dictionary<string, PicnicParameters>()
    {
        { "picnicl1fs.rsp", PicnicParameters.picnicl1fs },
        { "picnicl1ur.rsp", PicnicParameters.picnicl1ur },
        { "picnicl3fs.rsp", PicnicParameters.picnicl3fs },
        { "picnicl3ur.rsp", PicnicParameters.picnicl3ur },
        { "picnicl5fs.rsp", PicnicParameters.picnicl5fs },
        { "picnicl5ur.rsp", PicnicParameters.picnicl5ur },
        { "picnic3l1.rsp", PicnicParameters.picnic3l1 },
        { "picnic3l3.rsp", PicnicParameters.picnic3l3 },
        { "picnic3l5.rsp", PicnicParameters.picnic3l5 },
        { "picnicl1full.rsp", PicnicParameters.picnicl1full },
        { "picnicl3full.rsp", PicnicParameters.picnicl3full },
        { "picnicl5full.rsp", PicnicParameters.picnicl5full },
    };

    public static IEnumerable<object[]> TestVectorFiles_Data => TestVectorFiles.Select(v => new object[] { v });

    private static readonly IEnumerable<string> TestVectorFiles = Parameters.Keys;

    [Fact]
    public void TestPicnicRandom()
    {
        byte[] msg = Strings.ToByteArray("Hello World!");
        PicnicKeyPairGenerator keyGen = new PicnicKeyPairGenerator();

        SecureRandom random = new SecureRandom();

        keyGen.Init(new PicnicKeyGenerationParameters(random, PicnicParameters.picnic3l1));

        for (int i = 0; i != 100; i++)
        {
            AsymmetricCipherKeyPair keyPair = keyGen.GenerateKeyPair();

            // sign
            PicnicSigner signer = new PicnicSigner();
            PicnicPrivateKeyParameters skparam = (PicnicPrivateKeyParameters)keyPair.Private;
            signer.Init(true, skparam);

            byte[] sigGenerated = signer.GenerateSignature(msg);

            // verify
            PicnicSigner verifier = new PicnicSigner();
            PicnicPublicKeyParameters pkparam = (PicnicPublicKeyParameters)keyPair.Public;
            verifier.Init(false, pkparam);

            Assert.True(verifier.VerifySignature(msg, sigGenerated), "count = " + i);
        }
    }

    [Theory(Skip = BcTestData.SkipReason, SkipUnless = nameof(BcTestData.IsAvailable), SkipType = typeof(BcTestData))]
    [MemberData(nameof(TestVectorFiles_Data))]
    public void TV(string testVectorFile) =>
        PqcTestUtilities.RunTestVectors("pqc/crypto/picnic", testVectorFile, sampleOnly: true, RunTestVector);

    private static void RunTestVector(string path, Dictionary<string, string> data)
    {
        string count = data["count"];
        byte[] seed = Hex.Decode(data["seed"]);      // seed for SecureRandom
        int mlen = int.Parse(data["mlen"]);          // message length
        byte[] msg = Hex.Decode(data["msg"]);        // message
        byte[] pk = Hex.Decode(data["pk"]);          // public key
        byte[] sk = Hex.Decode(data["sk"]);          // private key
        int smlen = int.Parse(data["smlen"]);        // signature length
        byte[] sigExpected = Hex.Decode(data["sm"]); // signature

        NistSecureRandom random = new NistSecureRandom(seed, null);
        PicnicParameters picnicParameters = Parameters[path];

        PicnicKeyPairGenerator kpGen = new PicnicKeyPairGenerator();
        PicnicKeyGenerationParameters genParams = new PicnicKeyGenerationParameters(random, picnicParameters);

        //
        // Generate keys and test.
        //
        kpGen.Init(genParams);
        AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

        PicnicPublicKeyParameters pubParams = (PicnicPublicKeyParameters)PqcPublicKeyFactory.CreateKey(
            PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public));
        PicnicPrivateKeyParameters privParams = (PicnicPrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(
            PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private));

        Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), path + " " + count + ": public key");
        Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), path + " " + count + ": secret key");

        //
        // Signature test
        //
        PicnicSigner signer = new PicnicSigner();

        signer.Init(true, privParams);
        byte[] sigGenerated = signer.GenerateSignature(msg);
        byte[] attachedSig = Arrays.ConcatenateAll(UInt32_To_LE((uint)sigGenerated.Length), msg, sigGenerated);

        Assert.True(smlen == attachedSig.Length, path + " " + count + ": signature length");

        signer.Init(false, pubParams);
        Assert.True(signer.VerifySignature(msg, sigGenerated), (path + " " + count + ": signature verify"));
        Assert.True(Arrays.AreEqual(sigExpected, attachedSig), path + " " + count + ": signature gen match");
    }

    private static byte[] UInt32_To_LE(uint n)
    {
        byte[] bs = new byte[4];
        bs[0] = (byte)(n);
        bs[1] = (byte)(n >> 8);
        bs[2] = (byte)(n >> 16);
        bs[3] = (byte)(n >> 24);
        return bs;
    }
}
