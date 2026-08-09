using Xunit;

namespace CodeBrix.Cryptography.Cert.Tests; //was previously: Org.BouncyCastle.Cert.Tests;

public class MLDsaCredentialsTest
{
    [Fact]
    public void Sample_ML_DSA_44()
    {
        CheckSampleCredentials(SampleCredentials.ML_DSA_44);
    }

    [Fact]
    public void Sample_ML_DSA_65()
    {
        CheckSampleCredentials(SampleCredentials.ML_DSA_65);
    }

    [Fact]
    public void Sample_ML_DSA_87()
    {
        CheckSampleCredentials(SampleCredentials.ML_DSA_87);
    }

    private static void CheckSampleCredentials(SampleCredentials creds)
    {
        var cert = creds.Certificate;
        cert.Verify(cert.GetPublicKey());
    }
}
