using System;
using CodeBrix.Cryptography.Crypto.Engines;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Crypto.Tests; //was previously: Org.BouncyCastle.Crypto.Tests;

/// <summary> RC4 Test</summary>
public class RC4Test
	: ITest
{
    public string Name
    {
		get { return "RC4"; }
    }

	internal StreamCipherVectorTest[] tests = new StreamCipherVectorTest[]{
        new StreamCipherVectorTest(0, new RC4Engine(), new KeyParameter(Hex.Decode("0123456789ABCDEF")), "4e6f772069732074", "3afbb5c77938280d"),
        new StreamCipherVectorTest(0, new RC4Engine(), new KeyParameter(Hex.Decode("0123456789ABCDEF")), "68652074696d6520", "1cf1e29379266d59"),
        new StreamCipherVectorTest(0, new RC4Engine(), new KeyParameter(Hex.Decode("0123456789ABCDEF")), "666f7220616c6c20", "12fbb0c771276459")};

    public virtual ITestResult Perform()
    {
        for (int i = 0; i != tests.Length; i++)
        {
            ITestResult res = tests[i].Perform();

            if (!res.IsSuccessful())
            {
                return res;
            }
        }

		return new SimpleTestResult(true, Name + ": Okay");
    }

	[Fact]
    public void TestFunction()
    {
        string resultText = Perform().ToString();

		Assert.Equal(Name + ": Okay", resultText);
    }
}
