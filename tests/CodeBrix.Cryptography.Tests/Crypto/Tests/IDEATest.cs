using System;
using CodeBrix.Cryptography.Crypto.Engines;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Crypto.Tests; //was previously: Org.BouncyCastle.Crypto.Tests;

public class IdeaTest
    : CipherTest
{
    public override string Name
    {
        get { return "IDEA"; }
    }

    internal static SimpleTest[] tests = new SimpleTest[]
    {
        new BlockCipherVectorTest(0, new IdeaEngine(),
            new KeyParameter(Hex.Decode("00112233445566778899AABBCCDDEEFF")),
            "000102030405060708090a0b0c0d0e0f",
            "ed732271a7b39f475b4b2b6719f194bf"),
        new BlockCipherVectorTest(0, new IdeaEngine(),
            new KeyParameter(Hex.Decode("00112233445566778899AABBCCDDEEFF")),
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "b8bc6ed5c899265d2bcfad1fc6d4287d")
    };

    public IdeaTest()
        : base(tests, new IdeaEngine(), new KeyParameter(new byte[32]))
    {
    }

    [Fact]
    public void TestFunction()
    {
        string resultText = Perform().ToString();
        Assert.Equal(Name + ": Okay", resultText);
    }
}
