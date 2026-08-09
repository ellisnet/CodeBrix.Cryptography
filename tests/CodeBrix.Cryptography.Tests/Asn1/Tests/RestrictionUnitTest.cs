using System;
using CodeBrix.Cryptography.Asn1.IsisMtt.X509;
using CodeBrix.Cryptography.Asn1.X500;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Tests; //was previously: Org.BouncyCastle.Asn1.Tests;

public class RestrictionUnitTest
	: Asn1UnitTest
{
	public override string Name
	{
		get { return "Restriction"; }
	}

	public override void PerformTest()
	{
		DirectoryString res = new DirectoryString("test");
		Restriction restriction = new Restriction(res.GetString());

		checkConstruction(restriction, res);

		try
		{
			Restriction.GetInstance(new object());

			Fail("GetInstance() failed to detect bad object.");
		}
		catch (ArgumentException)
		{
			// expected
		}
	}

	private void checkConstruction(
		Restriction		restriction,
		DirectoryString	res)
	{
		checkValues(restriction, res);

		restriction = Restriction.GetInstance(restriction);

		checkValues(restriction, res);

		Asn1InputStream aIn = new Asn1InputStream(restriction.ToAsn1Object().GetEncoded());

		IAsn1String str = (IAsn1String) aIn.ReadObject();

		restriction = Restriction.GetInstance(str);

		checkValues(restriction, res);
	}

	private void checkValues(
		Restriction		restriction,
		DirectoryString	res)
	{
		checkMandatoryField("restriction", res, restriction.RestrictionString);
	}

	[Fact]
	public void TestFunction()
	{
		string resultText = Perform().ToString();

		Assert.Equal(Name + ": Okay", resultText);
	}
}
