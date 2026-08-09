using CodeBrix.Cryptography.Asn1.Pkcs;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Utilities.Encoders;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Tests; //was previously: Org.BouncyCastle.Asn1.Tests;

public class X509AltTest
{
    [Fact]
    public void TestX509AltTypes()
    {
        SubjectAltPublicKeyInfo subAlt = new SubjectAltPublicKeyInfo(
            new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance),
            new DerBitString(Hex.DecodeStrict("0102030405060708090807060504030201")));
        AltSignatureValue sigValAlt = new AltSignatureValue(Hex.DecodeStrict("0102030405060708090807060504030201"));

        AltSignatureAlgorithm sigAlgAlt = new AltSignatureAlgorithm(
            new AlgorithmIdentifier(PkcsObjectIdentifiers.MD5WithRsaEncryption, DerNull.Instance));
        AltSignatureAlgorithm sigAlgAlt2 = new AltSignatureAlgorithm(
            PkcsObjectIdentifiers.MD5WithRsaEncryption, DerNull.Instance);

        Assert.Equal(sigAlgAlt, sigAlgAlt2);

        var extGen = new X509ExtensionsGenerator();
        extGen.AddExtension(X509Extensions.SubjectAltPublicKeyInfo, false, subAlt);
        extGen.AddExtension(X509Extensions.AltSignatureAlgorithm, false, sigAlgAlt);
        extGen.AddExtension(X509Extensions.AltSignatureValue, false, sigValAlt);

        var exts = extGen.Generate();
        Assert.Equal(subAlt, SubjectAltPublicKeyInfo.FromExtensions(exts));
        Assert.Equal(sigAlgAlt, AltSignatureAlgorithm.FromExtensions(exts));
        Assert.Equal(sigValAlt, AltSignatureValue.FromExtensions(exts));
        Assert.Equal(subAlt, SubjectAltPublicKeyInfo.GetInstance(subAlt.GetEncoded()));
        Assert.Equal(sigAlgAlt, AltSignatureAlgorithm.GetInstance(sigAlgAlt.GetEncoded()));
        Assert.Equal(sigValAlt, AltSignatureValue.GetInstance(sigValAlt.GetEncoded()));
        Assert.Equal(subAlt, SubjectAltPublicKeyInfo.GetInstance(new DerTaggedObject(1, subAlt), true));
        Assert.Equal(sigAlgAlt, AltSignatureAlgorithm.GetInstance(new DerTaggedObject(1, sigAlgAlt), true));
        Assert.Equal(sigValAlt, AltSignatureValue.GetInstance(new DerTaggedObject(1, sigValAlt), true));
    }
}
