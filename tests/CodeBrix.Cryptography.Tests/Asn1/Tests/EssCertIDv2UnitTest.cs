using System;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Ess;
using CodeBrix.Cryptography.Asn1.Nist;
using CodeBrix.Cryptography.Asn1.X509;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Tests; //was previously: Org.BouncyCastle.Asn1.Tests;

public class EssCertIDv2UnitTest
: Asn1UnitTest
{
	public override string Name
	{
		get { return "ESSCertIDv2"; }
	}

	public override void PerformTest()
	{
		// check GetInstance on default algorithm.
		byte[] digest = new byte[32];
		EssCertIDv2 essCertIdv2 = new EssCertIDv2(
			new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256), digest);
		Asn1Object asn1Object = essCertIdv2.ToAsn1Object();

		EssCertIDv2.GetInstance(asn1Object);
	}

	[Fact]
    public void TestFunction()
    {
        string resultText = Perform().ToString();

        Assert.Equal(Name + ": Okay", resultText);
    }
}
