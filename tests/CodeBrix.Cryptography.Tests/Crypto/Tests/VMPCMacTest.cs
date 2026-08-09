using System;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Macs;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Crypto.Tests; //was previously: Org.BouncyCastle.Crypto.Tests;

public class VmpcMacTest
	: SimpleTest
{
	public override string Name
	{
		get { return "VMPC-MAC"; }
	}

	private static byte[] output1 = Hex.Decode("9BDA16E2AD0E284774A3ACBC8835A8326C11FAAD");

	public override void PerformTest()
	{
		ICipherParameters kp = new KeyParameter(
			Hex.Decode("9661410AB797D8A9EB767C21172DF6C7"));
		ICipherParameters kpwiv = new ParametersWithIV(kp,
			Hex.Decode("4B5C2F003E67F39557A8D26F3DA2B155"));

        int offset = 117;
        byte[] m = new byte[512];
		for (int i = 0; i < 256; i++)
		{
			m[offset + i] = (byte)i;
		}

        VmpcMac mac = new VmpcMac();
		mac.Init(kpwiv);

		mac.BlockUpdate(m, offset, 256);

		byte[] output = new byte[20];
		mac.DoFinal(output, 0);

		if (!Arrays.AreEqual(output, output1))
		{
			Fail("Fail",
				Hex.ToHexString(output1),
				Hex.ToHexString(output));
		}
	}

    [Fact]
	public void TestFunction()
	{
		string resultText = Perform().ToString();

		Assert.Equal(Name + ": Okay", resultText);
	}
}
