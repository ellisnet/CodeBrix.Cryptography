using System;
using CodeBrix.Cryptography.Crypto.Engines;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Crypto.Tests; //was previously: Org.BouncyCastle.Crypto.Tests;

/**
* Noekeon tester
*/
public class NoekeonTest
	: CipherTest
{
	private static readonly SimpleTest[] tests =
	{
		new BlockCipherVectorTest(0, new NoekeonEngine(),
			new KeyParameter(Hex.Decode("00000000000000000000000000000000")),
			"00000000000000000000000000000000",
			"b1656851699e29fa24b70148503d2dfc"),
		new BlockCipherVectorTest(1, new NoekeonEngine(),
			new KeyParameter(Hex.Decode("ffffffffffffffffffffffffffffffff")),
			"ffffffffffffffffffffffffffffffff",
			"2a78421b87c7d0924f26113f1d1349b2"),
		new BlockCipherVectorTest(2, new NoekeonEngine(),
			new KeyParameter(Hex.Decode("b1656851699e29fa24b70148503d2dfc")),
			"2a78421b87c7d0924f26113f1d1349b2",
			"e2f687e07b75660ffc372233bc47532c")
	};

	public NoekeonTest()
		: base(tests, new NoekeonEngine(), new KeyParameter(new byte[16]))
	{
	}

	public override string Name
	{
		get { return "Noekeon"; }
	}

	[Fact]
	public void TestFunction()
	{
		string resultText = Perform().ToString();

		Assert.Equal(Name + ": Okay", resultText);
	}
}
