using CodeBrix.Cryptography.Asn1.Icao;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Tests; //was previously: Org.BouncyCastle.Asn1.Tests;

public class CscaMasterListTest
    : SimpleTest
{
	public override string Name => "CscaMasterList";

	public override void PerformTest()
    {
		byte[] input = SimpleTest.GetTestData("asn1.masterlist-content.data");
		CscaMasterList parsedList = CscaMasterList.GetInstance(Asn1Object.FromByteArray(input));

		IsEquals("Cert structure parsing failed: incorrect length", 3, parsedList.GetCertStructs().Length);

		byte[] output = parsedList.GetEncoded();
		FailIf("Encoding failed after parse", !AreEqual(input, output));
	}

	[Fact]
    public void TestFunction()
    {
        string resultText = Perform().ToString();

		Assert.Equal(Name + ": Okay", resultText);
    }
}
