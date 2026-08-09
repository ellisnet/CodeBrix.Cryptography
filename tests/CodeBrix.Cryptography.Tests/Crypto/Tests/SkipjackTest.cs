using System;
using CodeBrix.Cryptography.Crypto.Engines;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Crypto.Tests; //was previously: Org.BouncyCastle.Crypto.Tests;

public class SkipjackTest
	: CipherTest
{
    public override string Name
    {
		get { return "SKIPJACK"; }
    }

    internal static SimpleTest[] tests = new SimpleTest[]{
        new BlockCipherVectorTest(0, new SkipjackEngine(), new KeyParameter(Hex.Decode("00998877665544332211")), "33221100ddccbbaa", "2587cae27a12d300")};

	public SkipjackTest()
		: base(tests, new SkipjackEngine(), new KeyParameter(new byte[16]))
	{
    }

	[Fact]
    public void TestFunction()
    {
        string resultText = Perform().ToString();

        Assert.Equal(Name + ": Okay", resultText);
    }
}
