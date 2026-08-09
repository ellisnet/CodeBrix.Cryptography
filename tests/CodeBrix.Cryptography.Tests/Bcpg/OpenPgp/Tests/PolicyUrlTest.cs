using System.IO;
using CodeBrix.Cryptography.Bcpg.Sig;
using CodeBrix.Cryptography.Utilities;
using Xunit;

namespace CodeBrix.Cryptography.Bcpg.OpenPgp.Tests; //was previously: Org.BouncyCastle.Bcpg.OpenPgp.Tests;

public class PolicyUrlTest
{
    [Fact]
    public void TestGetUrl()
    {
        PolicyUrl policyUrl = new PolicyUrl(true, "https://bouncycastle.org/policy/alice.txt");
        Assert.True(policyUrl.IsCritical());
        Assert.Equal("https://bouncycastle.org/policy/alice.txt", policyUrl.Url);

        policyUrl = new PolicyUrl(false, "https://bouncycastle.org/policy/bob.txt");
        Assert.False(policyUrl.IsCritical());
        Assert.Equal("https://bouncycastle.org/policy/bob.txt", policyUrl.Url);
    }

    [Fact]
    public void TestParsingFromSignature()
    {
        string signatureWithPolicyUrl = "-----BEGIN PGP SIGNATURE-----\n" +
            "\n" +
            "iKQEHxYKAFYFAmIRIAgJEDXXpSQjWzWvFiEEVSc3S9X9kRTsyfjqNdelJCNbNa8u\n" +
            "Gmh0dHBzOi8vZXhhbXBsZS5vcmcvfmFsaWNlL3NpZ25pbmctcG9saWN5LnR4dAAA\n" +
            "NnwBAImA2KdiS/7kLWoQpwc+A6N2PtAvLxG0gkZmGzYgRWvGAP9g4GLAA/GQ0plr\n" +
            "Xn7uLnOG49S1fFA9P+R1Dd8Qoa4+Dg==\n" +
            "=OPUu\n" +
            "-----END PGP SIGNATURE-----\n";

        MemoryStream byteIn = new MemoryStream(Strings.ToByteArray(signatureWithPolicyUrl), false);
        ArmoredInputStream armorIn = new ArmoredInputStream(byteIn);
        PgpObjectFactory objectFactory = new PgpObjectFactory(armorIn);

        PgpSignatureList signatures = (PgpSignatureList)objectFactory.NextPgpObject();
        PgpSignature signature = signatures[0];

        PolicyUrl policyUrl = signature.GetHashedSubPackets().GetPolicyUrl();
        Assert.Equal("https://example.org/~alice/signing-policy.txt", policyUrl.Url);

        PolicyUrl other = new PolicyUrl(false, "https://example.org/~alice/signing-policy.txt");

        MemoryStream first = new MemoryStream();
        policyUrl.Encode(first);

        MemoryStream second = new MemoryStream();
        other.Encode(second);

        Assert.True(Arrays.AreEqual(first.ToArray(), second.ToArray()));
    }
}
