using System;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Pqc.Crypto.Lms;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities;
using Xunit;

namespace CodeBrix.Cryptography.Pqc.Crypto.Tests; //was previously: Org.BouncyCastle.Pqc.Crypto.Tests;

public class HSSTest
{
    [Fact]
    public void TestOneLevelKeyGenAndSign()
    {
        byte[] msg = Strings.ToByteArray("Hello, world!");
        IAsymmetricCipherKeyPairGenerator kpGen = new HssKeyPairGenerator();

        var lmsParameters = new LmsParameters[]
        {
            new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
        };
        kpGen.Init(new HssKeyGenerationParameters(lmsParameters, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

        HssSigner signer = new HssSigner();

        signer.Init(true, kp.Private);

        byte[] sig = signer.GenerateSignature(msg);

        signer.Init(false, kp.Public);

        Assert.True(signer.VerifySignature(msg, sig));

        HssPublicKeyParameters hssPubKey = (HssPublicKeyParameters)kp.Public;

        hssPubKey.GenerateLmsContext(sig);
    }

    [Fact]
	public void TestKeyGenAndSign()
    {
        byte[] msg = Strings.ToByteArray("Hello, world!");
        IAsymmetricCipherKeyPairGenerator kpGen = new HssKeyPairGenerator();

        var lmsParameters = new LmsParameters[]
        {
            new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
            new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
        };
        kpGen.Init(new HssKeyGenerationParameters(lmsParameters, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

        HssSigner signer = new HssSigner();

        signer.Init(true, kp.Private);

        byte[] sig = signer.GenerateSignature(msg);

        signer.Init(false, kp.Public);

        Assert.True(signer.VerifySignature(msg, sig));
    }

    [Fact]
    public void TestHssKeyGenAndSign()
    {
        byte[] msg = Strings.ToByteArray("Hello, world!");

        IAsymmetricCipherKeyPairGenerator kpGen = new HssKeyPairGenerator();
        kpGen.Init(new HssKeyGenerationParameters(
            new LmsParameters[]{
                new LmsParameters(LMSigParameters.lms_sha256_n24_h5, LMOtsParameters.sha256_n24_w4),
                new LmsParameters(LMSigParameters.lms_sha256_n24_h5, LMOtsParameters.sha256_n24_w4)
            },
            new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

        HssSigner signer = new HssSigner();
        signer.Init(true, kp.Private);
        byte[] sig = signer.GenerateSignature(msg);

        signer.Init(false, kp.Public);
        Assert.True(signer.VerifySignature(msg, sig));
    }

    [Fact]
	public void TestKeyGenAndUsage()
    {
        byte[] msg = Strings.ToByteArray("Hello, world!");
        IAsymmetricCipherKeyPairGenerator kpGen = new HssKeyPairGenerator();

        kpGen.Init(new HssKeyGenerationParameters(
            new LmsParameters[]{
                new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
            }, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

        HssPrivateKeyParameters privKey = (HssPrivateKeyParameters)kp.Private;

        HssPublicKeyParameters pubKey = (HssPublicKeyParameters)kp.Public;

        LmsParameters lmsParam = pubKey.LmsPublicKey.GetLmsParameters();

        Assert.Equal(LMSigParameters.lms_sha256_n32_h5, lmsParam.LMSigParameters);
        Assert.Equal(LMOtsParameters.sha256_n32_w4, lmsParam.LMOtsParameters);

        HssSigner signer = new HssSigner();

        signer.Init(true, privKey);

        Assert.Equal(1024, privKey.GetUsagesRemaining());
        Assert.Equal(2, privKey.GetLmsParameters().Length);

        for (int i = 1; i <= 1024; i++)
        {
            signer.GenerateSignature(msg);

            Assert.Equal(i, privKey.GetIndex());
            Assert.Equal(1024 - i, privKey.GetUsagesRemaining());
        }
    }

	[Fact]
	public void TestKeyGenAndSignTwoSigsWithShard()
    {
        byte[] msg1 = Strings.ToByteArray("Hello, world!");
        byte[] msg2 = Strings.ToByteArray("Now is the time");

        IAsymmetricCipherKeyPairGenerator kpGen = new HssKeyPairGenerator();

        kpGen.Init(new HssKeyGenerationParameters(
            new LmsParameters[]{
                new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
            }, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

        HssPrivateKeyParameters privKey = ((HssPrivateKeyParameters)kp.Private).ExtractKeyShard(2);

        Assert.Equal(2, ((HssPrivateKeyParameters)kp.Private).GetIndex());

        HssSigner signer = new HssSigner();

        Assert.Equal(0, privKey.GetIndex());

        signer.Init(true, privKey);

        byte[] sig1 = signer.GenerateSignature(msg1);

        Assert.Equal(1, privKey.GetIndex());

        signer.Init(false, kp.Public);

        Assert.True(signer.VerifySignature(msg1, sig1));

        signer.Init(true, privKey);

        byte[] sig = signer.GenerateSignature(msg2);

        Assert.Equal(2, privKey.GetIndex());

        signer.Init(false, kp.Public);

        Assert.True(signer.VerifySignature(msg2, sig));

        signer.Init(true, privKey);
        try
        {
            sig = signer.GenerateSignature(msg2);
            Assert.Fail("no exception");
        }
        catch (Exception e)
        {
            Assert.Equal("hss private key shard is exhausted", e.Message);
        }

        signer.Init(true, ((HssPrivateKeyParameters)kp.Private));

        sig = signer.GenerateSignature(msg1);

        Assert.Equal(3, ((HssPrivateKeyParameters)kp.Private).GetIndex());

        Assert.False(Arrays.AreEqual(sig1, sig));

        signer.Init(false, kp.Public);

        Assert.True(signer.VerifySignature(msg1, sig1));
    }
}
