using System;
using System.IO;
using System.Text;
using CodeBrix.Cryptography.Utilities.Date;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Bcpg.OpenPgp.Tests; //was previously: Org.BouncyCastle.Bcpg.OpenPgp.Tests;

/**
* GPG compatability test vectors
*/
public class Dsa2Test
	//extends TestCase
{
	[Fact]
	public void TestK1024H160()
	{
		doSigVerifyTest("DSA-1024-160.pub", "dsa-1024-160-sign.gpg");
	}

	[Fact]
	public void TestK1024H224()
	{
		doSigVerifyTest("DSA-1024-160.pub", "dsa-1024-224-sign.gpg");
	}

	[Fact]
	public void TestK1024H256()
	{
		doSigVerifyTest("DSA-1024-160.pub", "dsa-1024-256-sign.gpg");
	}

	[Fact]
	public void TestK1024H384()
	{
		doSigVerifyTest("DSA-1024-160.pub", "dsa-1024-384-sign.gpg");
	}

	[Fact]
	public void TestK1024H512()
	{
		doSigVerifyTest("DSA-1024-160.pub", "dsa-1024-512-sign.gpg");
	}

	[Fact]
	public void TestK2048H224()
	{
		doSigVerifyTest("DSA-2048-224.pub", "dsa-2048-224-sign.gpg");
	}

	[Fact]
	public void TestK3072H256()
	{
		doSigVerifyTest("DSA-3072-256.pub", "dsa-3072-256-sign.gpg");
	}

	[Fact]
	public void TestK7680H384()
	{
		doSigVerifyTest("DSA-7680-384.pub", "dsa-7680-384-sign.gpg");
	}

	[Fact]
	public void TestK15360H512()
	{
		doSigVerifyTest("DSA-15360-512.pub", "dsa-15360-512-sign.gpg");
	}

	[Fact]
	public void TestGenerateK1024H224()
	{
		DoSigGenerateTest("DSA-1024-160.sec", "DSA-1024-160.pub", HashAlgorithmTag.Sha224);
	}

	[Fact]
	public void TestGenerateK1024H256()
	{
		DoSigGenerateTest("DSA-1024-160.sec", "DSA-1024-160.pub", HashAlgorithmTag.Sha256);
	}

	[Fact]
	public void TestGenerateK1024H384()
	{
		DoSigGenerateTest("DSA-1024-160.sec", "DSA-1024-160.pub", HashAlgorithmTag.Sha384);
	}

	[Fact]
	public void TestGenerateK1024H512()
	{
		DoSigGenerateTest("DSA-1024-160.sec", "DSA-1024-160.pub", HashAlgorithmTag.Sha512);
	}

	[Fact]
	public void TestGenerateK2048H256()
	{
		DoSigGenerateTest("DSA-2048-224.sec", "DSA-2048-224.pub", HashAlgorithmTag.Sha256);
	}

	[Fact]
	public void TestGenerateK2048H512()
	{
		DoSigGenerateTest("DSA-2048-224.sec", "DSA-2048-224.pub", HashAlgorithmTag.Sha512);
	}

	private void DoSigGenerateTest(
		string				privateKeyFile,
		string				publicKeyFile,
		HashAlgorithmTag	digest)
	{
		PgpSecretKeyRing		secRing = loadSecretKey(privateKeyFile);
		PgpPublicKeyRing		pubRing = loadPublicKey(publicKeyFile);
		string					data = "hello world!";
		byte[]					dataBytes = Encoding.ASCII.GetBytes(data);
		MemoryStream			bOut = new MemoryStream();
		MemoryStream			testIn = new MemoryStream(dataBytes, false);
		PgpSignatureGenerator	sGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Dsa, digest);

		sGen.InitSign(PgpSignature.BinaryDocument, secRing.GetSecretKey().ExtractPrivateKey("test".ToCharArray()));

		BcpgOutputStream bcOut = new BcpgOutputStream(bOut);

		sGen.GenerateOnePassVersion(false).Encode(bcOut);

		PgpLiteralDataGenerator lGen = new PgpLiteralDataGenerator();

		DateTime modificationTime = DateTimeUtilities.UnixMsToDateTime(
			DateTimeUtilities.CurrentUnixMs() / 1000 * 1000);

		using (var lOut = lGen.Open(
			new UncloseableStream(bcOut),
			PgpLiteralData.Binary,
			"_CONSOLE",
			dataBytes.Length,
			modificationTime))
		{
            int ch;
            while ((ch = testIn.ReadByte()) >= 0)
            {
                lOut.WriteByte((byte)ch);
                sGen.Update((byte)ch);
            }
        }

		sGen.Generate().Encode(bcOut);

		PgpObjectFactory        pgpFact = new PgpObjectFactory(bOut.ToArray());
		PgpOnePassSignatureList p1 = (PgpOnePassSignatureList)pgpFact.NextPgpObject();
		PgpOnePassSignature     ops = p1[0];

		Assert.Equal(digest, ops.HashAlgorithm);
		Assert.Equal(PublicKeyAlgorithmTag.Dsa, ops.KeyAlgorithm);

		PgpLiteralData          p2 = (PgpLiteralData)pgpFact.NextPgpObject();
		if (!p2.ModificationTime.Equals(modificationTime))
		{
			Assert.Fail("Modification time not preserved");
		}

		Stream dIn = p2.GetInputStream();

		ops.InitVerify(pubRing.GetPublicKey());

		{
			int ch;
			while ((ch = dIn.ReadByte()) >= 0)
			{
				ops.Update((byte)ch);
			}
        }

        PgpSignatureList p3 = (PgpSignatureList)pgpFact.NextPgpObject();
		PgpSignature sig = p3[0];

		Assert.Equal(digest, sig.HashAlgorithm);
		Assert.Equal(PublicKeyAlgorithmTag.Dsa, sig.KeyAlgorithm);

		Assert.True(ops.Verify(sig));
	}

	private void doSigVerifyTest(
		string	publicKeyFile,
		string	sigFile)
	{
		PgpPublicKeyRing publicKey = loadPublicKey(publicKeyFile);
		PgpObjectFactory pgpFact = loadSig(sigFile);

		PgpCompressedData c1 = (PgpCompressedData)pgpFact.NextPgpObject();

		pgpFact = new PgpObjectFactory(c1.GetDataStream());

		PgpOnePassSignatureList p1 = (PgpOnePassSignatureList)pgpFact.NextPgpObject();
		PgpOnePassSignature ops = p1[0];

		PgpLiteralData p2 = (PgpLiteralData)pgpFact.NextPgpObject();

		Stream dIn = p2.GetInputStream();

		ops.InitVerify(publicKey.GetPublicKey());

		int ch;
		while ((ch = dIn.ReadByte()) >= 0)
		{
			ops.Update((byte)ch);
		}

		PgpSignatureList p3 = (PgpSignatureList)pgpFact.NextPgpObject();

		Assert.True(ops.Verify(p3[0]));
	}

	private PgpObjectFactory loadSig(
		string sigName)
	{
		Stream fIn = SimpleTest.GetTestDataAsStream("openpgp.dsa.sigs." + sigName);

		return new PgpObjectFactory(fIn);
	}

	private PgpPublicKeyRing loadPublicKey(
		string keyName)
	{
		Stream fIn = SimpleTest.GetTestDataAsStream("openpgp.dsa.keys." + keyName);

		return new PgpPublicKeyRing(fIn);
	}

	private PgpSecretKeyRing loadSecretKey(
		string keyName)
	{
		Stream fIn = SimpleTest.GetTestDataAsStream("openpgp.dsa.keys." + keyName);

		return new PgpSecretKeyRing(fIn);
	}
}
