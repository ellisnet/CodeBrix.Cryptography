using System.Collections.Generic;
using System.IO;
using System.Text;
using CodeBrix.Cryptography.Asn1.Pkcs;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.X509;
using Xunit;

namespace CodeBrix.Cryptography.Cms.Tests; //was previously: Org.BouncyCastle.Cms.Tests;

public class AuthenticatedDataStreamTest
{
    private const string SignDN = "O=Bouncy Castle, C=AU";

    private static AsymmetricCipherKeyPair signKP;
    private static X509Certificate signCert;

    private const string OrigDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";

    private static AsymmetricCipherKeyPair origKP;
    private static X509Certificate origCert;

    private const string ReciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";

    private static AsymmetricCipherKeyPair reciKP;
    private static X509Certificate reciCert;

    private static AsymmetricCipherKeyPair origECKP;
    private static AsymmetricCipherKeyPair reciECKP;
    private static X509Certificate reciECCert;

    private static AsymmetricCipherKeyPair OrigECKP =>
        CmsTestUtil.InitKP(ref origECKP, CmsTestUtil.MakeECDsaKeyPair);

    private static AsymmetricCipherKeyPair OrigKP =>
        CmsTestUtil.InitKP(ref origKP, CmsTestUtil.MakeKeyPair);

    private static AsymmetricCipherKeyPair ReciECKP =>
        CmsTestUtil.InitKP(ref reciECKP, CmsTestUtil.MakeECDsaKeyPair);

    private static AsymmetricCipherKeyPair ReciKP => CmsTestUtil.InitKP(ref reciKP, CmsTestUtil.MakeKeyPair);

    private static AsymmetricCipherKeyPair SignKP => CmsTestUtil.InitKP(ref signKP, CmsTestUtil.MakeKeyPair);

    private static X509Certificate OrigCert => CmsTestUtil.InitCertificate(ref origCert,
        () => CmsTestUtil.MakeCertificate(OrigKP, OrigDN, SignKP, SignDN));

    private static X509Certificate ReciCert => CmsTestUtil.InitCertificate(ref reciCert,
        () => CmsTestUtil.MakeCertificate(ReciKP, ReciDN, SignKP, SignDN));

    private static X509Certificate ReciECCert => CmsTestUtil.InitCertificate(ref reciECCert,
        () => CmsTestUtil.MakeCertificate(ReciECKP, ReciDN, SignKP, SignDN));

    private static X509Certificate SignCert => CmsTestUtil.InitCertificate(ref signCert,
        () => CmsTestUtil.MakeCertificate(SignKP, SignDN, SignKP, SignDN));

    [Fact]
    public void TestKeyTransDESede()
    {
        TryKeyTrans(Encoding.ASCII.GetBytes("Eric H. Echidna"), CmsEnvelopedGenerator.DesEde3Cbc);
        // force multiple octet-string
        TryKeyTrans(new byte[2500], CmsEnvelopedGenerator.DesEde3Cbc);
    }

    [Fact]
    public void OriginatorInfo()
    {
        byte[] data = Encoding.ASCII.GetBytes("Eric H. Echidna");

        CmsAuthenticatedDataStreamGenerator adGen = new CmsAuthenticatedDataStreamGenerator();

        adGen.AddKeyTransRecipient(ReciCert);

        adGen.OriginatorInformation = new OriginatorInformation(new OriginatorInfoGenerator(OrigCert).Generate());

        MemoryStream bOut = new MemoryStream();
        using (Stream aOut = adGen.Open(bOut, CmsEnvelopedGenerator.DesEde3Cbc))
        {
            aOut.Write(data, 0, data.Length);
        }

        CmsAuthenticatedDataParser ad = new CmsAuthenticatedDataParser(bOut.ToArray());

        var originatorCerts = new List<X509Certificate>(
            ad.OriginatorInformation.GetCertificates().EnumerateMatches(null));
        Assert.Contains(OrigCert, originatorCerts);

        RecipientInformationStore recipients = ad.GetRecipientInfos();

        Assert.Equal(CmsEnvelopedGenerator.DesEde3Cbc, ad.MacAlgOid);

        var c = recipients.GetRecipients();

        Assert.Single(c);

        foreach (RecipientInformation recipient in c)
        {
            Assert.Equal(recipient.KeyEncryptionAlgOid, PkcsObjectIdentifiers.RsaEncryption.GetID());
            Assert.True(recipient.RecipientID.Match(ReciCert));

            byte[] recData = recipient.GetContent(ReciKP.Private);

            Assert.True(Arrays.AreEqual(data, recData));
            Assert.True(Arrays.AreEqual(ad.GetMac(), recipient.GetMac()));
        }
    }

    private void TryKeyTrans(byte[] data, string macAlg)
    {
        CmsAuthenticatedDataStreamGenerator adGen = new CmsAuthenticatedDataStreamGenerator();

        adGen.AddKeyTransRecipient(ReciCert);

        MemoryStream bOut = new MemoryStream();
        using (Stream aOut = adGen.Open(bOut, macAlg))
        {
            aOut.Write(data, 0, data.Length);
        }

        CmsAuthenticatedDataParser ad = new CmsAuthenticatedDataParser(bOut.ToArray());

        RecipientInformationStore recipients = ad.GetRecipientInfos();

        Assert.Equal(ad.MacAlgOid, macAlg);

        var c = recipients.GetRecipients();

        Assert.Single(c);

        foreach (RecipientInformation recipient in c)
        {
            Assert.Equal(recipient.KeyEncryptionAlgOid, PkcsObjectIdentifiers.RsaEncryption.Id);
            Assert.True(recipient.RecipientID.Match(ReciCert));

            byte[] recData = recipient.GetContent(ReciKP.Private);

            Assert.True(Arrays.AreEqual(data, recData));
            Assert.True(Arrays.AreEqual(ad.GetMac(), recipient.GetMac()));
        }
    }
}
