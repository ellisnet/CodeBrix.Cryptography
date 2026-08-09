using System;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace CodeBrix.Cryptography.Utilities.IO.Pem.Tests; //was previously: Org.BouncyCastle.Utilities.IO.Pem.Tests;

public class AllTests
{
    [Fact]
	public void TestPemLength()
	{
		for (int i = 1; i != 60; i++)
		{
			LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[i]);
		}

		LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[100]);
		LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[101]);
		LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[102]);
		LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[103]);

		LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[1000]);
		LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[1001]);
		LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[1002]);
		LengthTest("CERTIFICATE", new List<PemHeader>(), new byte[1003]);

		var headers = new List<PemHeader>();
		headers.Add(new PemHeader("Proc-Type", "4,ENCRYPTED"));
		headers.Add(new PemHeader("DEK-Info", "DES3,0001020304050607"));
		LengthTest("RSA PRIVATE KEY", headers, new byte[103]);
	}

    [Fact]
    public void TestMalformed()
    {
		try
		{
			using (var rd = new PemReader(new StringReader("-----BEGIN \n")))
			{
                rd.ReadPemObject();
            }
            Assert.Fail("must fail on malformed");
		}
		catch (IOException ioex)
        {
			Assert.Equal("ran out of data before consuming type", ioex.Message);
        }
    }

    [Fact]
    public void TestMalformedBase64()
    {
		// A PEM block with valid framing but a corrupt base64 body must surface as an IOException,
		// not a raw FormatException (found by mutational fuzzing; matches bc-java's DecoderException wrap).
		try
		{
			using (var rd = new PemReader(
				new StringReader("-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n")))
			{
                rd.ReadPemObject();
            }
            Assert.Fail("must fail on malformed base64");
		}
		catch (IOException ioex)
        {
			Assert.True(ioex.Message.StartsWith("malformed PEM data:"), "unexpected message: " + ioex.Message);
        }
    }

	private void LengthTest(string type, IList<PemHeader> headers, byte[] data)
	{
        PemObject pemObj = new PemObject(type, headers, data);

        StringWriter sw = new StringWriter();

		using (var pWrt = new PemWriter(sw))
		{
            pWrt.WriteObject(pemObj);
            Assert.Equal(sw.ToString().Length, pWrt.GetOutputSize(pemObj));
        }
    }
}
