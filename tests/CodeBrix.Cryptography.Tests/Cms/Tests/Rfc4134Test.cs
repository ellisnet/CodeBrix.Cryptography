using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Cms;
using CodeBrix.Cryptography.Asn1.Pkcs;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;
using CodeBrix.Cryptography.X509;
using Xunit;

namespace CodeBrix.Cryptography.Cms.Tests; //was previously: Org.BouncyCastle.Cms.Tests;

public class Rfc4134Test
{
	private static readonly byte[] exContent = GetRfc4134Data("ExContent.bin");
	private static readonly byte[] sha1 = Hex.Decode("406aec085279ba6e16022d9e0629c0229687dd48");

	[Fact]
	public void Test4_1()
	{
		byte[] data = GetRfc4134Data("4.1.bin");
		CmsSignedData signedData = new CmsSignedData(data);

		VerifySignatures(signedData);

		CmsSignedDataParser parser = new CmsSignedDataParser(data);

		VerifySignatures(parser);
	}

	[Fact]
	public void Test4_2()
	{
		byte[] data = GetRfc4134Data("4.2.bin");
		CmsSignedData signedData = new CmsSignedData(data);

		VerifySignatures(signedData);

		CmsSignedDataParser parser = new CmsSignedDataParser(data);

		VerifySignatures(parser);
	}

	[Fact]
	public void Test4_3()
	{
		CmsProcessableByteArray unencap = new CmsProcessableByteArray(exContent);
		byte[] data = GetRfc4134Data("4.3.bin");
		CmsSignedData signedData = new CmsSignedData(unencap, data);

		VerifySignatures(signedData, sha1);

		CmsSignedDataParser parser = new CmsSignedDataParser(
			new CmsTypedStream(unencap.GetInputStream()), data);

		VerifySignatures(parser);
	}

	[Fact]
	public void Test4_4()
	{
		byte[] data = GetRfc4134Data("4.4.bin");
		byte[] counterSigCert = GetRfc4134Data("AliceRSASignByCarl.cer");
		CmsSignedData signedData = new CmsSignedData(data);

		VerifySignatures(signedData, sha1);

		VerifySignerInfo4_4(GetFirstSignerInfo(signedData.GetSignerInfos()), counterSigCert);

		CmsSignedDataParser parser = new CmsSignedDataParser(data);

		VerifySignatures(parser);

		VerifySignerInfo4_4(GetFirstSignerInfo(parser.GetSignerInfos()), counterSigCert);
	}

	[Fact]
	public void Test4_5()
	{
		byte[] data = GetRfc4134Data("4.5.bin");
		CmsSignedData signedData = new CmsSignedData(data);

		VerifySignatures(signedData);

		CmsSignedDataParser parser = new CmsSignedDataParser(data);

		VerifySignatures(parser);
	}

	[Fact]
	public void Test4_6()
	{
		byte[] data = GetRfc4134Data("4.6.bin");
		CmsSignedData signedData = new CmsSignedData(data);

		VerifySignatures(signedData);

		CmsSignedDataParser parser = new CmsSignedDataParser(data);

		VerifySignatures(parser);
	}

	[Fact]
	public void Test4_7()
	{
		byte[] data = GetRfc4134Data("4.7.bin");
		CmsSignedData signedData = new CmsSignedData(data);

		VerifySignatures(signedData);

		CmsSignedDataParser parser = new CmsSignedDataParser(data);

		VerifySignatures(parser);
	}

	[Fact]
	public void Test5_1()
	{
		byte[] data = GetRfc4134Data("5.1.bin");
		CmsEnvelopedData envelopedData = new CmsEnvelopedData(data);

		VerifyEnvelopedData(envelopedData, CmsEnvelopedGenerator.DesEde3Cbc);

		CmsEnvelopedDataParser envelopedParser = new CmsEnvelopedDataParser(data);

		VerifyEnvelopedData(envelopedParser, CmsEnvelopedGenerator.DesEde3Cbc);
	}

    [Fact]
    public void Test5_2()
    {
        Properties.WithThreadProperty(Properties.CmsAllowLenientRsaPkcs1, bool.TrueString, () => {
            byte[] data = GetRfc4134Data("5.2.bin");
            CmsEnvelopedData envelopedData = new CmsEnvelopedData(data);

            VerifyEnvelopedData(envelopedData, CmsEnvelopedGenerator.RC2Cbc);

            CmsEnvelopedDataParser envelopedParser = new CmsEnvelopedDataParser(data);

            VerifyEnvelopedData(envelopedParser, CmsEnvelopedGenerator.RC2Cbc);
        });
    }

	private void VerifyEnvelopedData(CmsEnvelopedData envelopedData, string symAlgorithmOID)
	{
		byte[] privKeyData = GetRfc4134Data("BobPrivRSAEncrypt.pri");
		AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(privKeyData);
		Assert.True(privKey.IsPrivate);
		Assert.True(privKey is RsaKeyParameters);

		RecipientInformationStore recipients = envelopedData.GetRecipientInfos();

		Assert.Equal(envelopedData.EncryptionAlgOid, symAlgorithmOID);

		var c = recipients.GetRecipients();
		Assert.True(1 <= c.Count);
		Assert.True(2 >= c.Count);

		VerifyRecipient(c[0], privKey);

		if (c.Count == 2)
		{
			RecipientInformation recInfo = c[1];

			Assert.Equal(PkcsObjectIdentifiers.IdAlgCmsRC2Wrap.Id, recInfo.KeyEncryptionAlgOid);
		}
	}

	private void VerifyEnvelopedData(CmsEnvelopedDataParser envelopedParser, string symAlgorithmOID)
	{
		byte[] privKeyData = GetRfc4134Data("BobPrivRSAEncrypt.pri");
		AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(privKeyData);
		Assert.True(privKey.IsPrivate);
		Assert.True(privKey is RsaKeyParameters);

		RecipientInformationStore recipients = envelopedParser.GetRecipientInfos();

		Assert.Equal(envelopedParser.EncryptionAlgOid, symAlgorithmOID);

		var c = recipients.GetRecipients();
		Assert.True(1 <= c.Count);
		Assert.True(2 >= c.Count);

		VerifyRecipient((RecipientInformation)c[0], privKey);

		if (c.Count == 2)
		{
			RecipientInformation recInfo = (RecipientInformation)c[1];

			Assert.Equal(PkcsObjectIdentifiers.IdAlgCmsRC2Wrap.Id, recInfo.KeyEncryptionAlgOid);
		}
	}

	private void VerifyRecipient(RecipientInformation recipient, AsymmetricKeyParameter privKey)
	{
		Assert.True(privKey.IsPrivate);

		Assert.Equal(recipient.KeyEncryptionAlgOid, PkcsObjectIdentifiers.RsaEncryption.Id);

		byte[] recData = recipient.GetContent(privKey);

		Assert.True(Arrays.AreEqual(exContent, recData));
	}

	private void VerifySignerInfo4_4(SignerInformation signerInfo, byte[] counterSigCert)
	{
		VerifyCounterSignature(signerInfo, counterSigCert);

		VerifyContentHint(signerInfo);
	}

	private SignerInformation GetFirstSignerInfo(SignerInformationStore store)
	{
		var e = store.GetSigners().GetEnumerator();
		e.MoveNext();
		return e.Current;
	}

	private void VerifyCounterSignature(SignerInformation signInfo, byte[] certificate)
	{
		SignerInformation csi = GetFirstSignerInfo(signInfo.GetCounterSignatures());

		X509Certificate cert = new X509CertificateParser().ReadCertificate(certificate);

		Assert.True(csi.Verify(cert));
	}

	private void VerifyContentHint(SignerInformation signInfo)
	{
		Asn1.Cms.AttributeTable attrTable = signInfo.UnsignedAttributes;

		Asn1.Cms.Attribute attr = attrTable[CmsAttributes.ContentHint];

		Assert.Single(attr.AttrValues);

		Asn1EncodableVector v = new Asn1EncodableVector(
			new DerUtf8String("Content Hints Description Buffer"),
			CmsObjectIdentifiers.Data);

		Assert.True(attr.AttrValues[0].Equals(new DerSequence(v)));
	}

	private static void VerifySignatures(CmsSignedData s, byte[] contentDigest)
	{
		var x509Certs = s.GetCertificates();
		SignerInformationStore signers = s.GetSignerInfos();

		foreach (SignerInformation signer in signers.GetSigners())
		{
			var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

			var certEnum = certCollection.GetEnumerator();

			certEnum.MoveNext();
			X509Certificate cert = certEnum.Current;

			VerifySigner(signer, cert);

			if (contentDigest != null)
			{
				Assert.True(Arrays.AreEqual(contentDigest, signer.GetContentDigest()));
			}
		}
	}

	private static void VerifySignatures(CmsSignedData s) => VerifySignatures(s, null);

	private static void VerifySignatures(CmsSignedDataParser sp)
	{
        CmsTypedStream sc = sp.GetSignedContent();
        if (sc != null)
        {
            sc.Drain();
        }

		var x509Certs = sp.GetCertificates();
		SignerInformationStore signers = sp.GetSignerInfos();

		foreach (SignerInformation signer in signers.GetSigners())
		{
			var certCollection = x509Certs.EnumerateMatches(signer.SignerID);

			var certEnum = certCollection.GetEnumerator();
			certEnum.MoveNext();
			X509Certificate cert = certEnum.Current;

			VerifySigner(signer, cert);
		}
	}

    private static void VerifySigner(SignerInformation signer, X509Certificate cert)
    {
        if (cert.GetPublicKey() is DsaPublicKeyParameters dsa)
        {
            if (dsa.Parameters == null)
            {
                Assert.True(signer.Verify(GetInheritedKey(dsa)));
                return;
            }
        }

        Assert.True(signer.Verify(cert));
    }

    private static DsaPublicKeyParameters GetInheritedKey(DsaPublicKeyParameters dsaPubKey)
	{
		X509Certificate cert = new X509CertificateParser().ReadCertificate(
			GetRfc4134Data("CarlDSSSelf.cer"));

		DsaParameters dsaParams = ((DsaPublicKeyParameters)cert.GetPublicKey()).Parameters;

		return new DsaPublicKeyParameters(dsaPubKey.Y, dsaParams);
	}

	private static byte[] GetRfc4134Data(string name) => SimpleTest.GetTestData("rfc4134." + name);
}
