using System;
using CodeBrix.Cryptography.Crypto.Agreement;
using CodeBrix.Cryptography.Crypto.Generators;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Crypto.Tests; //was previously: Org.BouncyCastle.Crypto.Tests;

public class X448Test
    : SimpleTest
{
    private static readonly SecureRandom Random = new SecureRandom();

    public override string Name
    {
        get { return "X448"; }
    }

    [Fact]
    public void TestFunction()
    {
        string resultText = Perform().ToString();

        Assert.Equal(Name + ": Okay", resultText);
    }

    public override void PerformTest()
    {
        for (int i = 0; i < 10; ++i)
        {
            DoTestAgreement();
        }
    }

    private void DoTestAgreement()
    {
        IAsymmetricCipherKeyPairGenerator kpGen = new X448KeyPairGenerator();
        kpGen.Init(new X448KeyGenerationParameters(Random));

        AsymmetricCipherKeyPair kpA = kpGen.GenerateKeyPair();
        AsymmetricCipherKeyPair kpB = kpGen.GenerateKeyPair();

        X448Agreement agreeA = new X448Agreement();
        agreeA.Init(kpA.Private);
        byte[] secretA = new byte[agreeA.AgreementSize];
        agreeA.CalculateAgreement(kpB.Public, secretA, 0);

        X448Agreement agreeB = new X448Agreement();
        agreeB.Init(kpB.Private);
        byte[] secretB = new byte[agreeB.AgreementSize];
        agreeB.CalculateAgreement(kpA.Public, secretB, 0);

        if (!AreEqual(secretA, secretB))
        {
            Fail("X448 agreement failed");
        }
    }
}
