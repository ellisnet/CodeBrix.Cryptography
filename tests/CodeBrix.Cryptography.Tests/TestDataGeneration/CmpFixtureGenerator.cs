using System;
using System.IO;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Cmp;
using CodeBrix.Cryptography.Asn1.Crmf;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Cmp;
using CodeBrix.Cryptography.Crmf;
using Xunit;

namespace CodeBrix.Cryptography.TestDataGeneration;

/// <summary>
/// Regenerates test-data/cmp/sample_cr.der.
/// </summary>
/// <remarks>
/// ProtectedMessageTest.TestSampleCr loads a CMP certificate-request PKIMessage that is
/// PKMAC-protected with the password "TopSecret1234" and asserts the MAC verifies. Upstream
/// keeps that file in the unlicensed bc-test-data repository; this generates an equivalent
/// with this library, so the fixture is ours to redistribute.
/// </remarks>
public class CmpFixtureGenerator
{
    public static bool IsGenerationRequested =>
        Environment.GetEnvironmentVariable("CODEBRIX_CRYPTOGRAPHY_REGENERATE_TEST_DATA") == "1";

    private const long MaxFileBytes = 50L * 1024 * 1024;

    /// <summary>The password ProtectedMessageTest.TestSampleCr verifies the MAC with.</summary>
    private const string Password = "TopSecret1234";

    [Fact(Skip = "Utility: regenerates test-data/cmp. Set " +
                 "CODEBRIX_CRYPTOGRAPHY_REGENERATE_TEST_DATA=1 to run it.",
          SkipUnless = nameof(IsGenerationRequested))]
    public void RegenerateSampleCertificateRequest()
    {
        string dir = Path.Combine(TestDataPaths.RepositoryTestDataRoot(), "cmp");
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "sample_cr.der");

        var sender = new GeneralName(new X509Name("CN=CodeBrix.Cryptography Sample Sender"));
        var recipient = new GeneralName(new X509Name("CN=CodeBrix.Cryptography Sample Recipient"));

        var certTemplate = new CertTemplateBuilder()
            .SetSubject(new X509Name("CN=CodeBrix.Cryptography Sample Subject"))
            .Build();
        var certRequest = new CertRequest(1, certTemplate, controls: null);
        var certReqMsg = new CertReqMsg(certRequest, popo: null, regInfo: null);
        var certReqMessages = new CertReqMessages(certReqMsg);

        var macFactory = new PKMacBuilder().Build(Password.ToCharArray());

        ProtectedPkiMessage message = new ProtectedPkiMessageBuilder(sender, recipient)
            .SetBody(new PkiBody(PkiBody.TYPE_CERT_REQ, certReqMessages))
            .Build(macFactory);

        // Sanity check before writing: the fixture is only useful if it actually verifies.
        Assert.True(message.Verify(new PKMacBuilder(), Password.ToCharArray()));

        File.WriteAllBytes(path, message.ToAsn1Message().GetEncoded(Asn1Encodable.Der));

        Assert.True(new FileInfo(path).Length <= MaxFileBytes, path + " exceeds the 50 MB file limit");
    }
}
