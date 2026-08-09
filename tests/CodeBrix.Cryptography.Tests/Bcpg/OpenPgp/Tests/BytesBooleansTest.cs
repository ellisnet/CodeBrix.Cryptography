using System;
using CodeBrix.Cryptography.Bcpg.Sig;
using Xunit;

namespace CodeBrix.Cryptography.Bcpg.OpenPgp.Tests; //was previously: Org.BouncyCastle.Bcpg.OpenPgp.Tests;

public class BytesBooleansTest
{
    [Fact]
    public void TestParseFalse()
    {
        PrimaryUserId primaryUserID = new PrimaryUserId(true, false);
        byte[] bFalse = primaryUserID.GetData();

        Assert.Single(bFalse);
        Assert.Equal(0, bFalse[0]);
        Assert.False(primaryUserID.IsPrimaryUserId());
    }

    [Fact]
    public void TestParseTrue()
    {
        PrimaryUserId primaryUserID = new PrimaryUserId(true, true);
        byte[] bTrue = primaryUserID.GetData();

        Assert.Single(bTrue);
        Assert.Equal(1, bTrue[0]);
        Assert.True(primaryUserID.IsPrimaryUserId());
    }

    [Fact]
    public void TestParseTooShort()
    {
        PrimaryUserId primaryUserID = new PrimaryUserId(true, false, new byte[0]);
        byte[] bTooShort = primaryUserID.GetData();

        try
        {
            primaryUserID.IsPrimaryUserId();
            Assert.Fail("Should throw.");
        }
        catch (InvalidOperationException)
        {
            // expected.
        }
    }

    [Fact]
    public void TestParseTooLong()
    {
        PrimaryUserId primaryUserID = new PrimaryUserId(true, false, new byte[42]);
        byte[] bTooLong = primaryUserID.GetData();

        try
        {
            primaryUserID.IsPrimaryUserId();
            Assert.Fail("Should throw.");
        }
        catch (InvalidOperationException)
        {
            // expected.
        }
    }
}
