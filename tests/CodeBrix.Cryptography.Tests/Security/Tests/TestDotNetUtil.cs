using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Generators;
using CodeBrix.Cryptography.Crypto.Operators;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Math;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.X509;
using Xunit;
using SystemX509 = System.Security.Cryptography.X509Certificates;

namespace CodeBrix.Cryptography.Security.Tests; //was previously: Org.BouncyCastle.Security.Tests;

public class TestDotNetUtilities
{
    //#if NETCOREAPP1_0_OR_GREATER || NET47_OR_GREATER || NETSTANDARD1_6_OR_GREATER
    [Fact]
    public void TestECDsaInterop()
    {
        byte[] data = new byte[1024];

        for (int i = 0; i < 10; ++i)
        {
            var ecDsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] sig1 = ecDsa.SignData(data, HashAlgorithmName.SHA256);

            AsymmetricCipherKeyPair kp = DotNetUtilities.GetECDsaKeyPair(ecDsa);
            Assert.NotNull(kp.Private);
            Assert.NotNull(kp.Public);
            ISigner signer = SignerUtilities.GetSigner("SHA256withPLAIN-ECDSA");

            signer.Init(false, kp.Public);
            signer.BlockUpdate(data, 0, data.Length);
            Assert.True(signer.VerifySignature(sig1));

            signer.Init(true, kp.Private);
            signer.BlockUpdate(data, 0, data.Length);
            byte[] sig2 = signer.GenerateSignature();

            Assert.True(ecDsa.VerifyData(data, sig2, HashAlgorithmName.SHA256));
        }
    }

    [Fact]
    public void TestRsaInterop()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        for (int i = 0; i < 10; ++i)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(512);
            RSAParameters rp = rsa.ExportParameters(true);
            AsymmetricCipherKeyPair kp = DotNetUtilities.GetRsaKeyPair(rp);

            DotNetUtilities.ToRSA((RsaKeyParameters)kp.Public);
            // TODO This method appears to not work for private keys (when no CRT info)
            //DotNetUtilities.ToRSA((RsaKeyParameters)kp.Private);
            DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)kp.Private);
        }
    }

    [Fact]
    public void TestGetSubjectPublicKeyInfoDer()
    {
        RsaKeyPairGenerator pGen = new RsaKeyPairGenerator();
        pGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
        AsymmetricCipherKeyPair pair = pGen.GenerateKeyPair();

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.SetSerialNumber(BigInteger.One);
        certGen.SetIssuerDN(new X509Name("CN=Test Issuer"));
        certGen.SetSubjectDN(new X509Name("CN=Test Subject"));
        certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGen.SetNotAfter(DateTime.UtcNow.AddDays(1));
        certGen.SetPublicKey(pair.Public);

        ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", pair.Private);
        X509Certificate bcCert = certGen.Generate(signatureFactory);

        var dotNetCert = (SystemX509.X509Certificate2)DotNetUtilities.ToX509Certificate(bcCert);

        byte[] encoded = DotNetUtilities.GetSubjectPublicKeyInfoDer(dotNetCert);

        // OID for rsaEncryption (06 09 2a 86 48 86 f7 0d 01 01 01) followed by NULL (05 00)
        string hexEncoded = Hex.ToHexString(encoded).ToLowerInvariant();
        string expectedOidAndNull = "06092a864886f70d0101010500";

        Assert.True(hexEncoded.Contains(expectedOidAndNull), "GetSubjectPublicKeyInfoDer failed to produce correct RSA encoding with NULL parameters.");
    }

    [Fact]
    public void TestX509CertificateConversion()
    {
        if (OperatingSystem.IsBrowser())
            return;

        BigInteger DSAParaG = new BigInteger(Base64.Decode("AL0fxOTq10OHFbCf8YldyGembqEu08EDVzxyLL29Zn/t4It661YNol1rnhPIs+cirw+yf9zeCe+KL1IbZ/qIMZM="));
        BigInteger DSAParaP = new BigInteger(Base64.Decode("AM2b/UeQA+ovv3dL05wlDHEKJ+qhnJBsRT5OB9WuyRC830G79y0R8wuq8jyIYWCYcTn1TeqVPWqiTv6oAoiEeOs="));
        BigInteger DSAParaQ = new BigInteger(Base64.Decode("AIlJT7mcKL6SUBMmvm24zX1EvjNx"));
        BigInteger DSAPublicY = new BigInteger(Base64.Decode("TtWy2GuT9yGBWOHi1/EpCDa/bWJCk2+yAdr56rAcqP0eHGkMnA9s9GJD2nGU8sFjNHm55swpn6JQb8q0agrCfw=="));
        BigInteger DsaPrivateX = new BigInteger(Base64.Decode("MMpBAxNlv7eYfxLTZ2BItJeD31A="));

        DsaParameters para = new DsaParameters(DSAParaP, DSAParaQ, DSAParaG);
        DsaPrivateKeyParameters dsaPriv = new DsaPrivateKeyParameters(DsaPrivateX, para);
        DsaPublicKeyParameters dsaPub = new DsaPublicKeyParameters(DSAPublicY, para);

        var attrs = new Dictionary<DerObjectIdentifier, string>();
        attrs[X509Name.C] = "AU";
        attrs[X509Name.O] = "The Legion of the Bouncy Castle";
        attrs[X509Name.L] = "Melbourne";
        attrs[X509Name.ST] = "Victoria";
        attrs[X509Name.E] = "feedback-crypto@bouncycastle.org";

        var ord = new List<DerObjectIdentifier>(attrs.Keys);

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.SetSerialNumber(BigInteger.One);

        certGen.SetIssuerDN(new X509Name(ord, attrs));
        certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGen.SetNotAfter(DateTime.UtcNow.AddDays(1));
        certGen.SetSubjectDN(new X509Name(ord, attrs));
        certGen.SetPublicKey(dsaPub);

        X509Certificate cert = certGen.Generate(new Asn1SignatureFactory("SHA1WITHDSA", dsaPriv, null));

        cert.CheckValidity();
        cert.Verify(dsaPub);

        SystemX509.X509Certificate dotNetCert = DotNetUtilities.ToX509Certificate(cert);

        X509Certificate certCopy = DotNetUtilities.FromX509Certificate(dotNetCert);
        Assert.Equal(cert, certCopy);
        certCopy.CheckValidity();
        certCopy.Verify(dsaPub);

        if (dotNetCert is SystemX509.X509Certificate2 dotNetCert2)
        {
            X509Certificate certCopy2 = DotNetUtilities.FromX509Certificate(dotNetCert2);
            Assert.Equal(cert, certCopy2);
            certCopy2.CheckValidity();
            certCopy2.Verify(dsaPub);
        }
    }
}
