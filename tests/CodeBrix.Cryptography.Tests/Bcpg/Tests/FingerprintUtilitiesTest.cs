using System;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Encoders;
using Xunit;

namespace CodeBrix.Cryptography.Bcpg.Tests; //was previously: Org.BouncyCastle.Bcpg.Tests;

public class FingerprintUtilitiesTest
{
    [Fact]
    public void KeyIdFromTooShortFails()
    {
        byte[] decoded = new byte[1];
        try
        {
            FingerprintUtilities.KeyIDFromV4Fingerprint(decoded);
            Assert.Fail("Expected exception");
        }
        catch (ArgumentException)
        {
            // expected
        }
    }

    [Fact]
    public void V4KeyIdFromFingerprint()
    {
        string fingerprint = "1D018C772DF8C5EF86A1DCC9B4B509CB5936E03E";
        byte[] decoded = Hex.Decode(fingerprint);
        Assert.Equal(-5425419407118114754L, FingerprintUtilities.KeyIDFromV4Fingerprint(decoded));
    }

    [Fact]
    public void V6KeyIdFromFingerprint()
    {
        string fingerprint = "cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9";
        byte[] decoded = Hex.Decode(fingerprint);
        Assert.Equal(-3812177997909612905L, FingerprintUtilities.KeyIDFromV6Fingerprint(decoded));
    }

    [Fact]
    public void LibrePgpKeyIdFromFingerprint()
    {
        // v6 key-ids are derived from fingerprints the same way as LibrePGP does
        string fingerprint = "cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9";
        byte[] decoded = Hex.Decode(fingerprint);
        Assert.Equal(-3812177997909612905L, FingerprintUtilities.KeyIDFromLibrePgpFingerprint(decoded));
    }

    [Fact]
    public void KeyIdFromFingerprint()
    {
        Assert.Equal(-5425419407118114754L, FingerprintUtilities.KeyIDFromFingerprint(4, Hex.Decode("1D018C772DF8C5EF86A1DCC9B4B509CB5936E03E")));
        Assert.Equal(-3812177997909612905L, FingerprintUtilities.KeyIDFromFingerprint(5,
                Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")));
        Assert.Equal(-3812177997909612905L, FingerprintUtilities.KeyIDFromFingerprint(6,
                Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")));
    }

    [Fact]
    public void LeftMostEqualsRightMostFor8Bytes()
    {
        byte[] bytes = new byte[]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        Assert.Equal(FingerprintUtilities.LongFromLeftMostBytes(bytes), FingerprintUtilities.LongFromRightMostBytes(bytes));
        byte[] b = new byte[8];
        FingerprintUtilities.WriteKeyID(FingerprintUtilities.LongFromLeftMostBytes(bytes), b, 0);
        Assert.True(Arrays.AreEqual(bytes, b));
    }

    [Fact]
    public void WriteKeyIdToBytes()
    {
        byte[] bytes = new byte[12];
        long keyId = 72623859790382856L;
        FingerprintUtilities.WriteKeyID(keyId, bytes, 2);
        Assert.True(Arrays.AreEqual(new byte[]{ 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00 },
                bytes));

        try
        {
            byte[] b = new byte[7];
            FingerprintUtilities.WriteKeyID(0, b, 0);
            Assert.Fail("Expected ArgumentException for too short byte array.");
        }
        catch (ArgumentException)
        {
            // Expected
        }
    }

    // TODO[pgp] Implement PrettifyFingerprint method
    //[Test]
    //public void PrettifyFingerprint()
    //{
    //    Assert.Equal("1D01 8C77 2DF8 C5EF 86A1  DCC9 B4B5 09CB 5936 E03E", //        FingerprintUtilities.PrettifyFingerprint(Hex.Decode("1D018C772DF8C5EF86A1DCC9B4B509CB5936E03E")));
    //    Assert.Equal("CB186C4F 0609A697 E4D52DFA 6C722B0C  1F1E27C1 8A56708F 6525EC27 BAD9ACC9", //        FingerprintUtilities.PrettifyFingerprint(Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")));
    //}

    // TODO[pgp] Implement PrettifyFingerprint method
    //[Test]
    //public void PrettifyFingerprintReturnsHexForUnknownFormat()
    //{
    //    string fp = "C0FFEE1DECAFF0";
    //    Assert.Equal(fp, FingerprintUtilities.PrettifyFingerprint(Hex.Decode(fp)));
    //}
}
