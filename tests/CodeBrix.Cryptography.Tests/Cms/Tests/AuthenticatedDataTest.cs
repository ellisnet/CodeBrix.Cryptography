using System.Collections.Generic;
using System.Text;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Pkcs;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.X509;
using Xunit;

namespace CodeBrix.Cryptography.Cms.Tests; //was previously: Org.BouncyCastle.Cms.Tests;

public class AuthenticatedDataTest
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

    private static AsymmetricCipherKeyPair ReciKP =>
        CmsTestUtil.InitKP(ref reciKP, CmsTestUtil.MakeKeyPair);

    private static AsymmetricCipherKeyPair SignKP =>
        CmsTestUtil.InitKP(ref signKP, CmsTestUtil.MakeKeyPair);

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
        TryKeyTrans(PkcsObjectIdentifiers.DesEde3Cbc);
        TryKeyTransWithOaepOverride(PkcsObjectIdentifiers.DesEde3Cbc);
    }

    [Fact]
    public void TestKEKDESede()
    {
        TryKekAlgorithm(CmsTestUtil.MakeDesEde192Key(), new DerObjectIdentifier("1.2.840.113549.1.9.16.3.6"));
    }

    [Fact]
    public void TestPasswordAES256()
    {
        PasswordTest(CmsAuthenticatedDataGenerator.Aes256Cbc);
    }

    [Fact]
    public void TestECKeyAgree()
    {
        byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CmsAuthenticatedDataGenerator adGen = new CmsAuthenticatedDataGenerator();

        adGen.AddKeyAgreementRecipient(CmsAuthenticatedDataGenerator.ECDHSha1Kdf, OrigECKP.Private, OrigECKP.Public, ReciECCert, CmsAuthenticatedDataGenerator.Aes128Wrap);

        CmsAuthenticatedData ad = adGen.Generate(
            new CmsProcessableByteArray(data),
            CmsAuthenticatedDataGenerator.DesEde3Cbc);

        RecipientInformationStore recipients = ad.GetRecipientInfos();

        Assert.Equal(PkcsObjectIdentifiers.DesEde3Cbc, ad.MacAlgorithmID.Algorithm);

        var c = recipients.GetRecipients();

        Assert.Single(c);

        foreach (RecipientInformation recipient in c)
        {
            Assert.True(recipient.RecipientID.Match(ReciECCert));

            byte[] recData = recipient.GetContent(ReciECKP.Private);

            Assert.True(Arrays.AreEqual(data, recData));
            Assert.True(Arrays.AreEqual(ad.GetMac(), recipient.GetMac()));
        }
    }

    [Fact]
    public void TestEncoding()
    {
        byte[] data = Encoding.ASCII.GetBytes("Eric H. Echidna");

        CmsAuthenticatedDataGenerator adGen = new CmsAuthenticatedDataGenerator();

        adGen.AddKeyTransRecipient(ReciCert);

        CmsAuthenticatedData ad = adGen.Generate(
            new CmsProcessableByteArray(data),
            CmsAuthenticatedDataGenerator.DesEde3Cbc);

        ad = new CmsAuthenticatedData(ad.GetEncoded());

        RecipientInformationStore recipients = ad.GetRecipientInfos();

        Assert.Equal(PkcsObjectIdentifiers.DesEde3Cbc, ad.MacAlgorithmID.Algorithm);

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

    [Fact]
    public void OriginatorInfo()
    {
        byte[] data = Encoding.ASCII.GetBytes("Eric H. Echidna");

        CmsAuthenticatedDataGenerator adGen = new CmsAuthenticatedDataGenerator();

        adGen.OriginatorInformation = new OriginatorInformation(new OriginatorInfoGenerator(OrigCert).Generate());

        adGen.AddKeyTransRecipient(ReciCert);

        CmsAuthenticatedData ad = adGen.Generate(
            new CmsProcessableByteArray(data),
            CmsAuthenticatedDataGenerator.DesEde3Cbc);

        var originatorCerts = new List<X509Certificate>(
            ad.OriginatorInformation.GetCertificates().EnumerateMatches(null));
        Assert.Contains(OrigCert, originatorCerts);

        RecipientInformationStore recipients = ad.GetRecipientInfos();

        Assert.Equal(PkcsObjectIdentifiers.DesEde3Cbc, ad.MacAlgorithmID.Algorithm);

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

    private void TryKeyTrans(DerObjectIdentifier macAlgOid)
    {
        byte[] data = Encoding.ASCII.GetBytes("Eric H. Echidna");

        CmsAuthenticatedDataGenerator adGen = new CmsAuthenticatedDataGenerator();

        adGen.AddKeyTransRecipient(ReciCert);

        CmsAuthenticatedData ad = adGen.Generate(
            new CmsProcessableByteArray(data),
            macAlgOid);

        RecipientInformationStore recipients = ad.GetRecipientInfos();

        Assert.Equal(ad.MacAlgorithmID.Algorithm, macAlgOid);

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

    private void TryKeyTransWithOaepOverride(DerObjectIdentifier macAlgOid)
    {
        byte[] data = Encoding.ASCII.GetBytes("Eric H. Echidna");

        CmsAuthenticatedDataGenerator adGen = new CmsAuthenticatedDataGenerator();

        adGen.AddKeyTransRecipient("RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING", ReciCert);

        CmsAuthenticatedData ad = adGen.Generate(
            new CmsProcessableByteArray(data),
            macAlgOid);

        RecipientInformationStore recipients = ad.GetRecipientInfos();

        Assert.Equal(ad.MacAlgorithmID.Algorithm, macAlgOid);

        var c = recipients.GetRecipients();

        Assert.Single(c);

        foreach (RecipientInformation recipient in c)
        {
            Assert.Equal(recipient.KeyEncryptionAlgOid, PkcsObjectIdentifiers.IdRsaesOaep.Id);
            Assert.True(recipient.RecipientID.Match(ReciCert));

            byte[] recData = recipient.GetContent(ReciKP.Private);

            Assert.True(Arrays.AreEqual(data, recData));
            Assert.True(Arrays.AreEqual(ad.GetMac(), recipient.GetMac()));
        }
    }

    private void TryKekAlgorithm(KeyParameter kek, DerObjectIdentifier algOid)
    {
        byte[] data = Encoding.ASCII.GetBytes("Eric H. Echidna");

        CmsAuthenticatedDataGenerator adGen = new CmsAuthenticatedDataGenerator();

        byte[] kekId = new byte[] { 1, 2, 3, 4, 5 };

        // FIXME Will this work for macs?
        string keyAlgorithm = ParameterUtilities.GetCanonicalAlgorithmName(algOid.Id);

        adGen.AddKekRecipient(keyAlgorithm, kek, kekId);

        CmsAuthenticatedData ad = adGen.Generate(
            new CmsProcessableByteArray(data),
            CmsAuthenticatedDataGenerator.DesEde3Cbc);

        RecipientInformationStore recipients = ad.GetRecipientInfos();

        Assert.Equal(CmsAuthenticatedDataGenerator.DesEde3Cbc, ad.MacAlgOid);

        var c = recipients.GetRecipients();

        Assert.Single(c);

        foreach (RecipientInformation recipient in c)
        {
            Assert.Equal(recipient.KeyEncryptionAlgOid, algOid.Id);
            Assert.True(Arrays.AreEqual(recipient.RecipientID.KeyIdentifier, kekId));

            byte[] recData = recipient.GetContent(kek);

            Assert.True(Arrays.AreEqual(data, recData));
            Assert.True(Arrays.AreEqual(ad.GetMac(), recipient.GetMac()));
        }
    }

    private void PasswordTest(string algorithm)
    {
        byte[] data = Hex.Decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CmsAuthenticatedDataGenerator adGen = new CmsAuthenticatedDataGenerator();

        adGen.AddPasswordRecipient(new Pkcs5Scheme2PbeKey("password".ToCharArray(), new byte[20], 5), algorithm);

        CmsAuthenticatedData ad = adGen.Generate(
            new CmsProcessableByteArray(data),
            CmsAuthenticatedDataGenerator.DesEde3Cbc);

        RecipientInformationStore recipients = ad.GetRecipientInfos();

        Assert.Equal(CmsAuthenticatedDataGenerator.DesEde3Cbc, ad.MacAlgOid);

        var c = recipients.GetRecipients();

        Assert.Single(c);

        foreach (PasswordRecipientInformation recipient in c)
        {
            CmsPbeKey key = new Pkcs5Scheme2PbeKey("password".ToCharArray(), recipient.KeyDerivationAlgorithm);

            byte[] recData = recipient.GetContent(key);

            Assert.True(Arrays.AreEqual(data, recData));
            Assert.True(Arrays.AreEqual(ad.GetMac(), recipient.GetMac()));
        }
    }
}
