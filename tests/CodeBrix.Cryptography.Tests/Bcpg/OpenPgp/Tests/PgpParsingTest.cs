using System;
using System.IO;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Bcpg.OpenPgp.Tests; //was previously: Org.BouncyCastle.Bcpg.OpenPgp.Tests;

public class PgpParsingTest
	: SimpleTest
{
	public override void PerformTest()
	{
        Stream fIn = SimpleTest.GetTestDataAsStream("openpgp.bigpub.asc");
        Stream keyIn = PgpUtilities.GetDecoderStream(fIn);
        PgpPublicKeyRingBundle pubRings = new PgpPublicKeyRingBundle(keyIn);
	}

    public override string Name
	{
		get { return "PgpParsingTest"; }
	}

    [Fact]
	public void TestFunction()
	{
		string resultText = Perform().ToString();

		Assert.Equal(Name + ": Okay", resultText);
	}
}
