using System;
using System.Collections.Generic;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Cmp;
using CodeBrix.Cryptography.Asn1.Cms;
using CodeBrix.Cryptography.Asn1.Ess;
using CodeBrix.Cryptography.Asn1.Nist;
using CodeBrix.Cryptography.Asn1.Pkcs;
using CodeBrix.Cryptography.Cms;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Operators;
using CodeBrix.Cryptography.Math;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Collections;
using CodeBrix.Cryptography.X509;
using Xunit;

namespace CodeBrix.Cryptography.Tsp.Tests; //was previously: Org.BouncyCastle.Tsp.Tests;

public class TspTest
{
	private static AsymmetricKeyParameter privateKey;
	private static X509Certificate cert;
	private static IStore<X509Certificate> certs;

	static TspTest()
	{
		string signDN = "O=Bouncy Castle, C=AU";
		AsymmetricCipherKeyPair signKP = TspTestUtil.MakeKeyPair();
		X509Certificate signCert = TspTestUtil.MakeCACertificate(signKP, signDN, signKP, signDN);

		string origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
		AsymmetricCipherKeyPair origKP = TspTestUtil.MakeKeyPair();
		privateKey = origKP.Private;

		cert = TspTestUtil.MakeCertificate(origKP, origDN, signKP, signDN);

		var certList = new List<X509Certificate>();
		certList.Add(cert);
		certList.Add(signCert);

		certs = CollectionUtilities.CreateStore(certList);
	}

	[Fact]
	public void TestBasic()
	{
		TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			privateKey, cert, TspAlgorithms.Sha1, "1.2");

		tsTokenGen.SetCertificates(certs);

		TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
		TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

		TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

		TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

		tsResp = new TimeStampResponse(tsResp.GetEncoded());

		TimeStampToken  tsToken = tsResp.TimeStampToken;

		tsToken.Validate(cert);

		AttributeTable table = tsToken.SignedAttributes;

		Assert.NotNull(table[PkcsObjectIdentifiers.IdAASigningCertificate]);
	}

	[Fact]
	public void TestResponseValidation()
	{
		TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			privateKey, cert, TspAlgorithms.MD5, "1.2");

		tsTokenGen.SetCertificates(certs);

		TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
		TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

		TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

		TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

		tsResp = new TimeStampResponse(tsResp.GetEncoded());

		TimeStampToken tsToken = tsResp.TimeStampToken;

		tsToken.Validate(cert);

		//
		// check validation
		//
		tsResp.Validate(request);

		try
		{
			request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(101));

			tsResp.Validate(request);

			Assert.Fail("response validation failed on invalid nonce.");
		}
		catch (TspValidationException)
		{
			// ignore
		}

		try
		{
			request = reqGen.Generate(TspAlgorithms.Sha1, new byte[22], BigInteger.ValueOf(100));

			tsResp.Validate(request);

			Assert.Fail("response validation failed on wrong digest.");
		}
		catch (TspValidationException)
		{
			// ignore
		}

		try
		{
			request = reqGen.Generate(TspAlgorithms.MD5, new byte[20], BigInteger.ValueOf(100));

			tsResp.Validate(request);

			Assert.Fail("response validation failed on wrong digest.");
		}
		catch (TspValidationException)
		{
			// ignore
		}
	}

	[Fact]
	public void TestIncorrectHash()
	{
		TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			privateKey, cert, TspAlgorithms.Sha1, "1.2");

		tsTokenGen.SetCertificates(certs);

		TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
		TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[16]);

		TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

		TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

		tsResp = new TimeStampResponse(tsResp.GetEncoded());

		TimeStampToken tsToken = tsResp.TimeStampToken;

		if (tsToken != null)
		{
			Assert.Fail("incorrectHash - token not null.");
		}

		PkiFailureInfo failInfo = tsResp.GetFailInfo();

		if (failInfo == null)
		{
			Assert.Fail("incorrectHash - failInfo set to null.");
		}

		if (failInfo.IntValue != PkiFailureInfo.BadDataFormat)
		{
			Assert.Fail("incorrectHash - wrong failure info returned.");
		}
	}

	[Fact]
	public void TestBadAlgorithm()
	{
		TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			privateKey, cert, TspAlgorithms.Sha1, "1.2");

		tsTokenGen.SetCertificates(certs);

		TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
		TimeStampRequest request = reqGen.Generate(new DerObjectIdentifier("1.2.3.4.5"), new byte[20]);

		TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

		TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

		tsResp = new TimeStampResponse(tsResp.GetEncoded());

		TimeStampToken  tsToken = tsResp.TimeStampToken;

		if (tsToken != null)
		{
			Assert.Fail("badAlgorithm - token not null.");
		}

		PkiFailureInfo failInfo = tsResp.GetFailInfo();

		if (failInfo == null)
		{
			Assert.Fail("badAlgorithm - failInfo set to null.");
		}

		if (failInfo.IntValue != PkiFailureInfo.BadAlg)
		{
			Assert.Fail("badAlgorithm - wrong failure info returned.");
		}
	}

	[Fact]
	public void TestTimeNotAvailable()
	{
		TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			privateKey, cert, TspAlgorithms.Sha1, "1.2");

		tsTokenGen.SetCertificates(certs);

		TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
		TimeStampRequest request = reqGen.Generate(new DerObjectIdentifier("1.2.3.4.5"), new byte[20]);

		TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(
			tsTokenGen, TspAlgorithms.Allowed);

		TimeStampResponse tsResp = tsRespGen.Generate(request, new BigInteger("23"), null);

		tsResp = new TimeStampResponse(tsResp.GetEncoded());

		TimeStampToken tsToken = tsResp.TimeStampToken;

		if (tsToken != null)
		{
			Assert.Fail("timeNotAvailable - token not null.");
		}

		PkiFailureInfo failInfo = tsResp.GetFailInfo();

		if (failInfo == null)
		{
			Assert.Fail("timeNotAvailable - failInfo set to null.");
		}

		if (failInfo.IntValue != PkiFailureInfo.TimeNotAvailable)
		{
			Assert.Fail("timeNotAvailable - wrong failure info returned.");
		}
	}

	[Fact]
	public void TestBadPolicy()
	{
		TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			privateKey, cert, TspAlgorithms.Sha1, "1.2");

		tsTokenGen.SetCertificates(certs);

		TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

		reqGen.SetReqPolicy(new DerObjectIdentifier("1.1"));

		TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20]);

		TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed,
			new List<string>());

		TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

		tsResp = new TimeStampResponse(tsResp.GetEncoded());

		TimeStampToken tsToken = tsResp.TimeStampToken;

		if (tsToken != null)
		{
			Assert.Fail("badPolicy - token not null.");
		}

		PkiFailureInfo  failInfo = tsResp.GetFailInfo();

		if (failInfo == null)
		{
			Assert.Fail("badPolicy - failInfo set to null.");
		}

		if (failInfo.IntValue != PkiFailureInfo.UnacceptedPolicy)
		{
			Assert.Fail("badPolicy - wrong failure info returned.");
		}
	}

	[Fact]
	public void TestNullPolicy()
	{
		// null in request and token generator - should fail
		TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			privateKey, cert, TspAlgorithms.Sha1, null);

		tsTokenGen.SetCertificates(certs);

		TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

		TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20]);

		TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed, null);

		TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

		tsResp = new TimeStampResponse(tsResp.GetEncoded());

		TimeStampToken tsToken = tsResp.TimeStampToken;

		if (tsToken != null)
		{
			Assert.Fail("badPolicy - token not null.");
		}

		PkiFailureInfo failInfo = tsResp.GetFailInfo();

		if (failInfo == null)
		{
			Assert.Fail("badPolicy - failInfo set to null.");
		}

		if (failInfo.IntValue != PkiFailureInfo.UnacceptedPolicy)
		{
			Assert.Fail("badPolicy - wrong failure info returned.");
		}

		// request specifies policy, token generator doesn't - should work
		reqGen = new TimeStampRequestGenerator();

		reqGen.SetReqPolicy(new DerObjectIdentifier("1.1"));

		request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20]);

		tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed, null);

	    tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(24), DateTime.UtcNow);

		tsResp = new TimeStampResponse(tsResp.GetEncoded());

		tsToken = tsResp.TimeStampToken;

		Assert.Equal("1.1", tsToken.TimeStampInfo.Policy); // policy should be picked up off request
	}

	[Fact]
	public void TestCertReq()
	{
		TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			privateKey, cert, TspAlgorithms.MD5, "1.2");

		tsTokenGen.SetCertificates(certs);

		TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

		//
		// request with certReq false
		//
		reqGen.SetCertReq(false);

		TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

		TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

		TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

		tsResp = new TimeStampResponse(tsResp.GetEncoded());

		TimeStampToken tsToken = tsResp.TimeStampToken;

		Assert.Null(tsToken.TimeStampInfo.GenTimeAccuracy); // check for abscence of accuracy

		Assert.Equal("1.2", tsToken.TimeStampInfo.Policy);

		try
		{
			tsToken.Validate(cert);
		}
		catch (TspValidationException)
		{
			Assert.Fail("certReq(false) verification of token failed.");
		}

		IStore<X509Certificate> respCerts = tsToken.GetCertificates();

		var certsColl = new List<X509Certificate>(respCerts.EnumerateMatches(null));

		if (certsColl.Count != 0)
		{
			Assert.Fail("certReq(false) found certificates in response.");
		}
	}

	[Fact]
	public void TestTokenEncoding()
	{
		TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			privateKey, cert, TspAlgorithms.Sha1, "1.2.3.4.5.6");

		tsTokenGen.SetCertificates(certs);

		TimeStampRequestGenerator  reqGen = new TimeStampRequestGenerator();
		TimeStampRequest           request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));
		TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);
		TimeStampResponse          tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

		tsResp = new TimeStampResponse(tsResp.GetEncoded());

		TimeStampResponse tsResponse = new TimeStampResponse(tsResp.GetEncoded());

		if (!Arrays.AreEqual(tsResponse.GetEncoded(), tsResp.GetEncoded())
			|| !Arrays.AreEqual(tsResponse.TimeStampToken.GetEncoded(),
						tsResp.TimeStampToken.GetEncoded()))
		{
			Assert.Fail("Test failed: reached code that should not have been reached.");
		}
	}

	[Fact]
	public void TestAccuracyZeroCerts()
	{
		TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			privateKey, cert, TspAlgorithms.MD5, "1.2");

		tsTokenGen.SetCertificates(certs);

		tsTokenGen.SetAccuracySeconds(1);
		tsTokenGen.SetAccuracyMillis(2);
		tsTokenGen.SetAccuracyMicros(3);

		TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
		TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

		TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

		TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

		tsResp = new TimeStampResponse(tsResp.GetEncoded());

		TimeStampToken  tsToken = tsResp.TimeStampToken;

		tsToken.Validate(cert);

		//
		// check validation
		//
		tsResp.Validate(request);

		//
		// check tstInfo
		//
		TimeStampTokenInfo tstInfo = tsToken.TimeStampInfo;

		//
		// check accuracy
		//
		GenTimeAccuracy accuracy = tstInfo.GenTimeAccuracy;

		Assert.Equal(1, accuracy.Seconds);
		Assert.Equal(2, accuracy.Millis);
		Assert.Equal(3, accuracy.Micros);

		Assert.Equal(BigInteger.ValueOf(23), tstInfo.SerialNumber);

		Assert.Equal("1.2", tstInfo.Policy);

		//
		// test certReq
		//
		IStore<X509Certificate> store = tsToken.GetCertificates();

		var certificates = new List<X509Certificate>(store.EnumerateMatches(null));

		Assert.Empty(certificates);
	}

	[Fact]
	public void TestAccuracyWithCertsAndOrdering()
	{
		TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			privateKey, cert, TspAlgorithms.MD5, "1.2.3");

		tsTokenGen.SetCertificates(certs);

		tsTokenGen.SetAccuracySeconds(3);
		tsTokenGen.SetAccuracyMillis(1);
		tsTokenGen.SetAccuracyMicros(2);

		tsTokenGen.SetOrdering(true);

		TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

		reqGen.SetCertReq(true);

		TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

		Assert.True(request.CertReq);

		TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

		TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

		tsResp = new TimeStampResponse(tsResp.GetEncoded());

		TimeStampToken tsToken = tsResp.TimeStampToken;

		tsToken.Validate(cert);

		//
		// check validation
		//
		tsResp.Validate(request);

		//
		// check tstInfo
		//
		TimeStampTokenInfo tstInfo = tsToken.TimeStampInfo;

		//
		// check accuracy
		//
		GenTimeAccuracy accuracy = tstInfo.GenTimeAccuracy;

		Assert.Equal(3, accuracy.Seconds);
		Assert.Equal(1, accuracy.Millis);
		Assert.Equal(2, accuracy.Micros);

		Assert.Equal(BigInteger.ValueOf(23), tstInfo.SerialNumber);

		Assert.Equal("1.2.3", tstInfo.Policy);

		Assert.True(tstInfo.IsOrdered);

		Assert.Equal(tstInfo.Nonce, BigInteger.ValueOf(100));

		//
		// test certReq
		//
		IStore<X509Certificate> store = tsToken.GetCertificates();

		var certificates = new List<X509Certificate>(store.EnumerateMatches(null));

		Assert.Equal(2, certificates.Count);
	}

	[Fact]
	public void TestNoNonce()
	{
		TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			privateKey, cert, TspAlgorithms.MD5, "1.2.3");

		tsTokenGen.SetCertificates(certs);

		TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
		TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20]);

		Assert.False(request.CertReq);

		TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

		TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(24), DateTime.UtcNow);

		tsResp = new TimeStampResponse(tsResp.GetEncoded());

		TimeStampToken tsToken = tsResp.TimeStampToken;

		tsToken.Validate(cert);

		//
		// check validation
		//
		tsResp.Validate(request);

		//
		// check tstInfo
		//
		TimeStampTokenInfo tstInfo = tsToken.TimeStampInfo;

		//
		// check accuracy
		//
		GenTimeAccuracy accuracy = tstInfo.GenTimeAccuracy;

		Assert.Null(accuracy);

		Assert.Equal(BigInteger.ValueOf(24), tstInfo.SerialNumber);

		Assert.Equal("1.2.3", tstInfo.Policy);

		Assert.False(tstInfo.IsOrdered);

		Assert.Null(tstInfo.Nonce);

		//
		// test certReq
		//
		IStore<X509Certificate> store = tsToken.GetCertificates();

		var certificates = new List<X509Certificate>(store.EnumerateMatches(null));

		Assert.Empty(certificates);
	}

	[Fact]
	public void TestBasicSha256()
    {
		SignerInfoGenerator sInfoGenerator = MakeInfoGenerator(privateKey, cert, TspAlgorithms.Sha256, null, null);
		TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			sInfoGenerator,
			Asn1DigestFactory.Get(NistObjectIdentifiers.IdSha256),new DerObjectIdentifier("1.2"),true);

		tsTokenGen.SetCertificates(certs);

		TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
		TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha256, new byte[32]);

		Assert.False(request.CertReq);

		TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

		TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

		tsResp = new TimeStampResponse(tsResp.GetEncoded());

		TimeStampToken tsToken = tsResp.TimeStampToken;

		tsToken.Validate(cert);

		TimeStampTokenInfo tstInfo = tsToken.TimeStampInfo;

		AttributeTable table = tsToken.SignedAttributes;

		Asn1.Cms.Attribute r = table[PkcsObjectIdentifiers.IdAASigningCertificateV2];
		Assert.NotNull(r);
		Assert.Equal(PkcsObjectIdentifiers.IdAASigningCertificateV2, r.AttrType);
		Asn1Set set = r.AttrValues;
		SigningCertificateV2 sCert = SigningCertificateV2.GetInstance(set[0]);

		Asn1.X509.IssuerSerial issSerNum = sCert.GetCerts()[0].IssuerSerial;

		Assert.Equal(cert.SerialNumber, issSerNum.Serial.Value);
	}

    internal static SignerInfoGenerator MakeInfoGenerator(AsymmetricKeyParameter key, X509Certificate cert,
		string digestOID, AttributeTable signedAttr, AttributeTable unsignedAttr)
    {
        TspUtil.ValidateCertificate(cert);

		//
		// Add the ESSCertID attribute
		//
		IDictionary<DerObjectIdentifier, object> signedAttrs;
		if (signedAttr != null)
		{
			signedAttrs = signedAttr.ToDictionary();
		}
		else
		{
			signedAttrs = new Dictionary<DerObjectIdentifier, object>();
		}

		string digestName = TspTestUtil.GetDigestAlgName(digestOID);
		string signatureName = digestName + "with" + TspTestUtil.GetEncryptionAlgName(
			TspTestUtil.GetEncOid(key, digestOID));

		Asn1SignatureFactory sigfact = new Asn1SignatureFactory(signatureName, key);
		return new SignerInfoGeneratorBuilder()
			.WithSignedAttributeGenerator(
				new DefaultSignedAttributeTableGenerator(new AttributeTable(signedAttrs)))
			.WithUnsignedAttributeGenerator(
				new SimpleAttributeTableGenerator(unsignedAttr))
			.Build(sigfact, cert);
	}
}
