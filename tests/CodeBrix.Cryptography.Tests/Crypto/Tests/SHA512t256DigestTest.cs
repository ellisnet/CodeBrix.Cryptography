using CodeBrix.Cryptography.Crypto.Digests;
using Xunit;

namespace CodeBrix.Cryptography.Crypto.Tests; //was previously: Org.BouncyCastle.Crypto.Tests;

/**
 * standard vector test for SHA-512/256 from FIPS 180-4.
 *
 * Note, only the last 2 message entries are FIPS originated..
 */
public class Sha512t256DigestTest
    : DigestTest
{
    private static readonly string[] Messages =
    {
        "",
        "a",
        "abc",
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    };

    private static readonly string[] Digests =
    {
        "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
        "455e518824bc0601f9fb858ff5c37d417d67c2f8e0df2babe4808858aea830f8",
        "53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23",
        "3928E184FB8690F840DA3988121D31BE65CB9D3EF83EE6146FEAC861E19B563A",
    };

    // 1 million 'a'
    private const string MillionADigest = "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21";

    public Sha512t256DigestTest()
        : base(new Sha512tDigest(256), Messages, Digests)
    {
    }

    public override void PerformTest()
    {
        base.PerformTest();

        MillionATest(MillionADigest);
    }

    protected override IDigest CloneDigest(IDigest digest) => new Sha512tDigest((Sha512tDigest)digest);

    [Fact]
    public void TestFunction()
    {
        string resultText = Perform().ToString();

        Assert.Equal(Name + ": Okay", resultText);
    }
}
