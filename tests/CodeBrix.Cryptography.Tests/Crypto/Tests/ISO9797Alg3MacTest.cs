using System.Text;
using CodeBrix.Cryptography.Crypto.Engines;
using CodeBrix.Cryptography.Crypto.Macs;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Crypto.Tests; //was previously: Org.BouncyCastle.Crypto.Tests;

public class ISO9797Alg3MacTest
	: SimpleTest
{
	static byte[] keyBytes = Hex.Decode("7CA110454A1A6E570131D9619DC1376E");
	static byte[] ivBytes = Hex.Decode("0000000000000000");

	static byte[] input1 = Encoding.ASCII.GetBytes("Hello World !!!!");

	static byte[] output1 = Hex.Decode("F09B856213BAB83B");

	public ISO9797Alg3MacTest()
	{
	}

	public override void PerformTest()
	{
		KeyParameter key = new KeyParameter(keyBytes);
		IBlockCipher cipher = new DesEngine();
		IMac mac = new ISO9797Alg3Mac(cipher);

		//
		// standard DAC - zero IV
		//
		mac.Init(key);

		mac.BlockUpdate(input1, 0, input1.Length);

		byte[] outBytes = new byte[8];

		mac.DoFinal(outBytes, 0);

		if (!AreEqual(outBytes, output1))
		{
			Fail("Failed - expected " + Hex.ToHexString(output1) + " got " + Hex.ToHexString(outBytes));
		}

		//
		//  reset
		//
		mac.Reset();

		mac.Init(key);

		for (int i = 0; i != input1.Length / 2; i++)
		{
			mac.Update(input1[i]);
		}

		mac.BlockUpdate(input1, input1.Length / 2, input1.Length - (input1.Length / 2));

		mac.DoFinal(outBytes, 0);

		if (!AreEqual(outBytes, output1))
		{
			Fail("Reset failed - expected " + Hex.ToHexString(output1) + " got " + Hex.ToHexString(outBytes));
		}
	}

	public override string Name
	{
		get { return "ISO9797Alg3Mac"; }
	}

	[Fact]
	public void TestFunction()
	{
		string resultText = Perform().ToString();

		Assert.Equal(Name + ": Okay", resultText);
	}
}
