using System;
using CodeBrix.Cryptography.Asn1.Misc;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Tests; //was previously: Org.BouncyCastle.Asn1.Tests;

public class NetscapeCertTypeTest
	: SimpleTest
{
	public override string Name
	{
		get { return "NetscapeCertType"; }
	}

	public override void PerformTest()
	{
		BitStringConstantTester.testFlagValueCorrect(0, NetscapeCertType.SslClient);
		BitStringConstantTester.testFlagValueCorrect(1, NetscapeCertType.SslServer);
		BitStringConstantTester.testFlagValueCorrect(2, NetscapeCertType.Smime);
		BitStringConstantTester.testFlagValueCorrect(3, NetscapeCertType.ObjectSigning);
		BitStringConstantTester.testFlagValueCorrect(4, NetscapeCertType.Reserved);
		BitStringConstantTester.testFlagValueCorrect(5, NetscapeCertType.SslCA);
		BitStringConstantTester.testFlagValueCorrect(6, NetscapeCertType.SmimeCA);
		BitStringConstantTester.testFlagValueCorrect(7, NetscapeCertType.ObjectSigningCA);
	}

	[Fact]
	public void TestFunction()
	{
		string resultText = Perform().ToString();

		Assert.Equal(Name + ": Okay", resultText);
	}
}
