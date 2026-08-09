using System;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Tests; //was previously: Org.BouncyCastle.Asn1.Tests;

public class ReasonFlagsTest
	: SimpleTest
{
	public override string Name
	{
		get { return "ReasonFlags"; }
	}

	public override void PerformTest()
	{
		BitStringConstantTester.testFlagValueCorrect(0, ReasonFlags.Unused);
		BitStringConstantTester.testFlagValueCorrect(1, ReasonFlags.KeyCompromise);
		BitStringConstantTester.testFlagValueCorrect(2, ReasonFlags.CACompromise);
		BitStringConstantTester.testFlagValueCorrect(3, ReasonFlags.AffiliationChanged);
		BitStringConstantTester.testFlagValueCorrect(4, ReasonFlags.Superseded);
		BitStringConstantTester.testFlagValueCorrect(5, ReasonFlags.CessationOfOperation);
		BitStringConstantTester.testFlagValueCorrect(6, ReasonFlags.CertificateHold);
		BitStringConstantTester.testFlagValueCorrect(7, ReasonFlags.PrivilegeWithdrawn);
		BitStringConstantTester.testFlagValueCorrect(8, ReasonFlags.AACompromise);
	}

	[Fact]
	public void TestFunction()
	{
		string resultText = Perform().ToString();

		Assert.Equal(Name + ": Okay", resultText);
	}
}
