using System;
using CodeBrix.Cryptography.Asn1.Nist;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Tests; //was previously: Org.BouncyCastle.Asn1.Tests;

public class KMacParamsTest
    : SimpleTest
{
    public override string Name
    {
        get { return "KMacParamsTest"; }
    }

    public override void PerformTest()
    {
        Assert.True(Arrays.AreEqual(new KMacWithShake128Params(256).GetEncoded(), new DerSequence().GetEncoded()));
        Assert.True(Arrays.AreEqual(new KMacWithShake256Params(512).GetEncoded(), new DerSequence().GetEncoded()));

        Assert.True(Arrays.AreEqual(new KMacWithShake128Params(512).GetEncoded(), new DerSequence(DerInteger.ValueOf(512)).GetEncoded()));
        Assert.True(Arrays.AreEqual(new KMacWithShake256Params(256).GetEncoded(), new DerSequence(DerInteger.ValueOf(256)).GetEncoded()));

        Assert.True(Arrays.AreEqual(new KMacWithShake128Params(512).GetEncoded(), KMacWithShake128Params.GetInstance(new DerSequence(DerInteger.ValueOf(512))).GetEncoded()));
        Assert.True(Arrays.AreEqual(new KMacWithShake256Params(256).GetEncoded(), KMacWithShake256Params.GetInstance(new DerSequence(DerInteger.ValueOf(256))).GetEncoded()));

        byte[] customizationString = Strings.ToByteArray("hello, world!");

        Assert.True(Arrays.AreEqual(new KMacWithShake128Params(512, customizationString).GetEncoded(), new DerSequence(
            new Asn1Encodable[] { DerInteger.ValueOf(512), new DerOctetString(customizationString) }).GetEncoded()));
        Assert.True(Arrays.AreEqual(new KMacWithShake256Params(256, customizationString).GetEncoded(), new DerSequence(
            new Asn1Encodable[] { DerInteger.ValueOf(256), new DerOctetString(customizationString) }).GetEncoded()));

        Assert.True(Arrays.AreEqual(new KMacWithShake128Params(512, customizationString).GetEncoded(),
            KMacWithShake128Params.GetInstance(
                new DerSequence(new Asn1Encodable[] { DerInteger.ValueOf(512), new DerOctetString(customizationString) })).GetEncoded()));
        Assert.True(Arrays.AreEqual(new KMacWithShake256Params(256, customizationString).GetEncoded(),
            KMacWithShake256Params.GetInstance(
                new DerSequence(new Asn1Encodable[] { DerInteger.ValueOf(256), new DerOctetString(customizationString) })).GetEncoded()));

        Assert.True(Arrays.AreEqual(new KMacWithShake128Params(256, customizationString).GetEncoded(), new DerSequence(
            new Asn1Encodable[] { new DerOctetString(customizationString) }).GetEncoded()));
        Assert.True(Arrays.AreEqual(new KMacWithShake256Params(512, customizationString).GetEncoded(), new DerSequence(
            new Asn1Encodable[] { new DerOctetString(customizationString) }).GetEncoded()));

        Assert.True(Arrays.AreEqual(new KMacWithShake128Params(256, customizationString).GetEncoded(),
            KMacWithShake128Params.GetInstance(
                new DerSequence(new Asn1Encodable[] { new DerOctetString(customizationString) })).GetEncoded()));
        Assert.True(Arrays.AreEqual(new KMacWithShake256Params(512, customizationString).GetEncoded(),
            KMacWithShake256Params.GetInstance(
                new DerSequence(new Asn1Encodable[] { new DerOctetString(customizationString) })).GetEncoded()));

        KMacWithShake128Params p128 = new KMacWithShake128Params(256, customizationString);
        Assert.Equal(256, p128.OutputLength);
        Assert.True(Arrays.AreEqual(customizationString, p128.CustomizationString));
        Assert.True(p128 == KMacWithShake128Params.GetInstance(p128));

        KMacWithShake256Params p256 = new KMacWithShake256Params(512, customizationString);
        Assert.Equal(512, p256.OutputLength);
        Assert.True(Arrays.AreEqual(customizationString, p256.CustomizationString));
        Assert.True(p256 == KMacWithShake256Params.GetInstance(p256));

        p128 = new KMacWithShake128Params(512);
        Assert.Equal(512, p128.OutputLength);
        Assert.True(Arrays.AreEqual(new byte[0], p128.CustomizationString));

        p256 = new KMacWithShake256Params(256);
        Assert.Equal(256, p256.OutputLength);
        Assert.True(Arrays.AreEqual(new byte[0], p256.CustomizationString));
    }

    [Fact]
    public void TestFunction()
    {
        string resultText = Perform().ToString();

        Assert.Equal(resultText, Name + ": Okay");
    }
}
