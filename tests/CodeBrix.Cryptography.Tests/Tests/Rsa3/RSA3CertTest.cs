using System;
using System.IO;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.OpenSsl;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities.Test;
using CodeBrix.Cryptography.X509;
using Xunit;

namespace CodeBrix.Cryptography.Tests.Rsa3; //was previously: Org.BouncyCastle.Tests.Rsa3;

/**
* Marius Schilder's Bleichenbacher's Forgery Attack Tests
*/
public class RSA3CertTest
	//extends TestCase
{
	[Fact]
	public void TestA()
	{
		doTest("self-testcase-A.pem");
	}

	[Fact]
	public void TestB()
	{
		doTest("self-testcase-B.pem");
	}

	[Fact]
	public void TestC()
	{
		doTest("self-testcase-C.pem");
	}

	[Fact]
	public void TestD()
	{
		doTest("self-testcase-D.pem");
	}

	[Fact]
	public void TestE()
	{
		doTest("self-testcase-E.pem");
	}

	[Fact]
	public void TestF()
	{
		doTest("self-testcase-F.pem");
	}

	[Fact]
	public void TestG()
	{
		doTest("self-testcase-G.pem");
	}

	[Fact]
	public void TestH()
	{
		doTest("self-testcase-H.pem");
	}

	[Fact]
	public void TestI()
	{
		doTest("self-testcase-I.pem");
	}

	[Fact]
	public void TestJ()
	{
		doTest("self-testcase-J.pem");
	}

	[Fact]
	public void TestL()
	{
		doTest("self-testcase-L.pem");
	}

	private void doTest(
		string certName)
	{
		X509Certificate cert = loadCert(certName);
		byte[] tbs = cert.GetTbsCertificate();
		ISigner sig = SignerUtilities.GetSigner(cert.SigAlgName);

		sig.Init(false, cert.GetPublicKey());

		sig.BlockUpdate(tbs, 0, tbs.Length);

		Assert.False(sig.VerifySignature(cert.GetSignature()));
	}

	private X509Certificate loadCert(
		string certName)
	{
		Stream s = SimpleTest.GetTestDataAsStream("rsa3." + certName);
		TextReader tr = new StreamReader(s);
		using (var rd = new PemReader(tr))
		{
            return (X509Certificate)rd.ReadObject();
        }
    }
}
