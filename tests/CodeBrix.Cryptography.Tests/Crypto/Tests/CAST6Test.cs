using System;
using CodeBrix.Cryptography.Crypto.Engines;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Crypto.Tests; //was previously: Org.BouncyCastle.Crypto.Tests;

/// <remarks>Cast6 tester - vectors from http://www.ietf.org/rfc/rfc2612.txt</remarks>
public class Cast6Test : CipherTest
{
    public override string Name
    {
		get { return "CAST6"; }
    }

	internal static SimpleTest[] tests = new SimpleTest[]
	{
		new BlockCipherVectorTest(0, new Cast6Engine(),
			new KeyParameter(Hex.Decode("2342bb9efa38542c0af75647f29f615d")),
			"00000000000000000000000000000000",
			"c842a08972b43d20836c91d1b7530f6b"),
		new BlockCipherVectorTest(0, new Cast6Engine(),
			new KeyParameter(Hex.Decode("2342bb9efa38542cbed0ac83940ac298bac77a7717942863")),
			"00000000000000000000000000000000",
			"1b386c0210dcadcbdd0e41aa08a7a7e8"),
		new BlockCipherVectorTest(0, new Cast6Engine(),
			new KeyParameter(Hex.Decode("2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604")),
			"00000000000000000000000000000000",
			"4f6a2038286897b9c9870136553317fa")
	};

    public Cast6Test()
		: base(tests, new Cast6Engine(), new KeyParameter(new byte[16]))
    {
    }

	[Fact]
    public void TestFunction()
    {
        string resultText = Perform().ToString();
        Assert.Equal(Name + ": Okay", resultText);
    }
}
