using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;
using CodeBrix.Cryptography.X509.Extension;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Tests; //was previously: Org.BouncyCastle.Asn1.Tests;

public class SubjectKeyIdentifierTest
    : SimpleTest
{
    private static readonly byte[] pubKeyInfo = Base64.Decode(
        "MFgwCwYJKoZIhvcNAQEBA0kAMEYCQQC6wMMmHYMZszT/7bNFMn+gaZoiWJLVP8ODRuu1C2jeAe" +
        "QpxM+5Oe7PaN2GNy3nBE4EOYkB5pMJWA0y9n04FX8NAgED");

    private static readonly byte[] shaID = Hex.Decode("d8128a06d6c2feb0865994a2936e7b75b836a021");
    private static readonly byte[] shaTruncID = Hex.Decode("436e7b75b836a021");

    public override string Name => "SubjectKeyIdentifier";

    public override void PerformTest()
    {
        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.GetInstance(pubKeyInfo);
        SubjectKeyIdentifier ski = X509ExtensionUtilities.CreateSubjectKeyIdentifier(pubInfo);

        if (!Arrays.AreEqual(shaID, ski.GetKeyIdentifier()))
        {
            Fail("SHA-1 ID does not match");
        }

        ski = SubjectKeyIdentifier.CreateTruncatedSha1KeyIdentifier(pubInfo);

        if (!Arrays.AreEqual(shaTruncID, ski.GetKeyIdentifier()))
        {
            Fail("truncated SHA-1 ID does not match");
        }
    }

    [Fact]
    public void TestFunction()
    {
        string resultText = Perform().ToString();

        Assert.Equal(Name + ": Okay", resultText);
    }
}
