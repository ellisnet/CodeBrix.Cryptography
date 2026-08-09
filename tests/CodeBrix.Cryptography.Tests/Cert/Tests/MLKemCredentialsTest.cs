using Xunit;

namespace CodeBrix.Cryptography.Cert.Tests; //was previously: Org.BouncyCastle.Cert.Tests;

public class MLKemCredentialsTest
{
    [Fact]
    public void Sample_ML_KEM_512()
    {
        CheckSampleCredentials(SampleCredentials.ML_KEM_512, SampleCredentials.ML_DSA_44);
    }

    [Fact]
    public void Sample_ML_KEM_768()
    {
        CheckSampleCredentials(SampleCredentials.ML_KEM_768, SampleCredentials.ML_DSA_65);
    }

    [Fact]
    public void Sample_ML_KEM_1024()
    {
        CheckSampleCredentials(SampleCredentials.ML_KEM_1024, SampleCredentials.ML_DSA_87);
    }

    private static void CheckSampleCredentials(SampleCredentials subject, SampleCredentials issuer)
    {
        subject.Certificate.Verify(issuer.Certificate.GetPublicKey());
    }
}
