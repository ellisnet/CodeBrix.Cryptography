using Xunit;

namespace CodeBrix.Cryptography.Cert.Tests; //was previously: Org.BouncyCastle.Cert.Tests;

public class SlhDsaCredentialsTest
{
    [Fact]
    public void Sample_SLH_DSA_SHA2_128S()
    {
        CheckSampleCredentials(SampleCredentials.SLH_DSA_SHA2_128S);
    }

    private static void CheckSampleCredentials(SampleCredentials creds)
    {
        var cert = creds.Certificate;
        cert.Verify(cert.GetPublicKey());
    }
}
