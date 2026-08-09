using System;
using CodeBrix.Cryptography.Crypto.Engines;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Crypto.Tests; //was previously: Org.BouncyCastle.Crypto.Tests;

/// <remarks>Cast tester - vectors from http://www.ietf.org/rfc/rfc2144.txt</remarks>
public class Cast5Test
	: CipherTest
{
    public override string Name
    {
		get { return "Cast5"; }
    }

	internal static SimpleTest[] testlist = new SimpleTest[]{
        new BlockCipherVectorTest(0, new Cast5Engine(), new KeyParameter(Hex.Decode("0123456712345678234567893456789A")), "0123456789ABCDEF", "238B4FE5847E44B2"),
        new BlockCipherVectorTest(0, new Cast5Engine(), new KeyParameter(Hex.Decode("01234567123456782345")), "0123456789ABCDEF", "EB6A711A2C02271B"),
        new BlockCipherVectorTest(0, new Cast5Engine(), new KeyParameter(Hex.Decode("0123456712")), "0123456789ABCDEF", "7Ac816d16E9B302E")};

	public Cast5Test()
		: base(testlist , new Cast5Engine(), new KeyParameter(new byte[16]))
    {
    }

	[Fact]
    public void TestFunction()
    {
        string resultText = Perform().ToString();

        Assert.Equal(Name + ": Okay", resultText);
    }
}
