using System;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Digests;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Crypto.Tests; //was previously: Org.BouncyCastle.Crypto.Tests;

/**
 * standard vector test for MD4 from RFC 1320.
 */
public class MD4DigestTest
    : DigestTest
{
    static private string[] messages =
    {
        "",
        "a",
        "abc",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    };

    static private string[] digests =
    {
        "31d6cfe0d16ae931b73c59d7e0c089c0",
        "bde52cb31de33e46245e05fbdbd6fb24",
        "a448017aaf21d8525fc10ae87aa6729d",
        "e33b4ddc9c38f2199c3e7b164fcc0536"
    };

    public MD4DigestTest()
        : base(new MD4Digest(), messages, digests)
    {
    }

    protected override IDigest CloneDigest(IDigest digest)
    {
        return new MD4Digest((MD4Digest)digest);
    }

    [Fact]
    public void TestFunction()
    {
        string resultText = Perform().ToString();

        Assert.Equal(Name + ": Okay", resultText);
    }
}
