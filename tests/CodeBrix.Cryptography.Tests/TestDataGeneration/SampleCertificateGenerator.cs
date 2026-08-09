using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Cms;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Generators;
using CodeBrix.Cryptography.Crypto.Operators;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Math;
using CodeBrix.Cryptography.Pkcs;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Collections;
using CodeBrix.Cryptography.Utilities.IO.Pem;
using CodeBrix.Cryptography.X509;
using Xunit;

namespace CodeBrix.Cryptography.TestDataGeneration;

/// <summary>
/// Regenerates the sample credentials under test-data/pkix/cert/.
/// </summary>
/// <remarks>
/// Upstream BouncyCastle keeps these fixtures in a separate bc-test-data repository that
/// carries no licence. This fork cannot redistribute those files, so it generates
/// equivalents with this library itself; everything under test-data/ is therefore either
/// authored here or already MIT-licensed from bc-csharp.
///
/// This is a utility, not a test. It only runs when
/// CODEBRIX_CRYPTOGRAPHY_REGENERATE_TEST_DATA=1 is set, and it writes into the repository
/// working tree rather than the build output.
/// </remarks>
public class SampleCertificateGenerator
{
    public static bool IsGenerationRequested =>
        Environment.GetEnvironmentVariable("CODEBRIX_CRYPTOGRAPHY_REGENERATE_TEST_DATA") == "1";

    // GitHub warns above 50 MB for a single file. Nothing generated here comes close, but
    // the guard keeps that true if the fixture set ever grows.
    private const long MaxFileBytes = 50L * 1024 * 1024;

    [Fact(Skip = "Utility: regenerates test-data/pkix/cert. Set " +
                 "CODEBRIX_CRYPTOGRAPHY_REGENERATE_TEST_DATA=1 to run it.",
          SkipUnless = nameof(IsGenerationRequested))]
    public void RegenerateSampleCredentials()
    {
        string testData = TestDataPaths.RepositoryTestDataRoot();
        var random = new SecureRandom();

        var written = new List<string>();

        // MLKemCredentialsTest pairs each ML-KEM certificate with a specific ML-DSA
        // issuer (512 with 44, 768 with 65, 1024 with 87), so the ML-DSA credentials are
        // generated first and then used to sign the matching ML-KEM certificate. ML-KEM
        // keys cannot sign, so their certificates cannot be self-signed.
        var mlDsaIssuers =
            new Dictionary<string, (AsymmetricCipherKeyPair KeyPair, X509Name Subject, X509Certificate Certificate)>();

        foreach (var p in new[]
        {
            (Name: "ML-DSA-44.pem", Parameters: MLDsaParameters.ml_dsa_44),
            (Name: "ML-DSA-65.pem", Parameters: MLDsaParameters.ml_dsa_65),
            (Name: "ML-DSA-87.pem", Parameters: MLDsaParameters.ml_dsa_87),
        })
        {
            var keyPair = GenerateMLDsa(p.Parameters, random);
            // An ML-DSA key can sign, so its certificate is self-signed.
            string algorithm = p.Name.Substring(0, p.Name.Length - ".pem".Length);
            var subject = new X509Name("CN=CodeBrix.Cryptography Sample " + algorithm + ", O=CodeBrix, C=US");
            var cert = IssueCertificate(subject, keyPair.Public, subject,
                new Asn1SignatureFactory(algorithm, keyPair.Private, random), random);
            mlDsaIssuers[algorithm] = (keyPair, subject, cert);
            written.Add(WriteCredentials(testData, "pkix/cert/mldsa", p.Name, keyPair, cert));
        }

        foreach (var p in new[]
        {
            (Name: "ML-KEM-512.pem", Parameters: MLKemParameters.ml_kem_512, Issuer: "ML-DSA-44"),
            (Name: "ML-KEM-768.pem", Parameters: MLKemParameters.ml_kem_768, Issuer: "ML-DSA-65"),
            (Name: "ML-KEM-1024.pem", Parameters: MLKemParameters.ml_kem_1024, Issuer: "ML-DSA-87"),
        })
        {
            var generator = new MLKemKeyPairGenerator();
            generator.Init(new MLKemKeyGenerationParameters(random, p.Parameters));
            var keyPair = generator.GenerateKeyPair();

            var issuer = mlDsaIssuers[p.Issuer];
            string algorithm = p.Name.Substring(0, p.Name.Length - ".pem".Length);
            var subject = new X509Name("CN=CodeBrix.Cryptography Sample " + algorithm + ", O=CodeBrix, C=US");
            var cert = IssueCertificate(subject, keyPair.Public, issuer.Subject,
                new Asn1SignatureFactory(p.Issuer, issuer.KeyPair.Private, random), random);
            written.Add(WriteCredentials(testData, "pkix/cert/mlkem", p.Name, keyPair, cert));
        }

        {
            var generator = new SlhDsaKeyPairGenerator();
            generator.Init(new SlhDsaKeyGenerationParameters(random, SlhDsaParameters.slh_dsa_sha2_128s));
            var keyPair = generator.GenerateKeyPair();

            var subject = new X509Name("CN=CodeBrix.Cryptography Sample SLH-DSA-SHA2-128S, O=CodeBrix, C=US");
            var cert = IssueCertificate(subject, keyPair.Public, subject,
                new Asn1SignatureFactory("SLH-DSA-SHA2-128S", keyPair.Private, random), random);
            written.Add(WriteCredentials(testData, "pkix/cert/slhdsa", "SLH-DSA-SHA2-128S.pem", keyPair, cert));
        }

        // SignedDataTest verifies each of these against the matching ML-DSA sample
        // certificate generated above, so they are produced from the same key material
        // in the same run rather than loaded back from disk.
        foreach (var p in new[]
        {
            (Name: "SignedData_ML-DSA-44.pem", Algorithm: "ML-DSA-44"),
            (Name: "SignedData_ML-DSA-65.pem", Algorithm: "ML-DSA-65"),
            (Name: "SignedData_ML-DSA-87.pem", Algorithm: "ML-DSA-87"),
        })
        {
            var issuer = mlDsaIssuers[p.Algorithm];
            written.Add(WriteSignedData(testData, "pkix/cms/mldsa", p.Name, p.Algorithm,
                issuer.KeyPair, issuer.Certificate, random));
        }

        Assert.Equal(10, written.Count);
        foreach (string path in written)
        {
            Assert.True(new FileInfo(path).Length <= MaxFileBytes, path + " exceeds the 50 MB file limit");
        }
    }

    /// <summary>
    /// Writes a CMS SignedData whose SignerInfo verifies against <paramref name="certificate"/>.
    /// </summary>
    private static string WriteSignedData(string testDataRoot, string relativeDir, string fileName,
        string algorithm, AsymmetricCipherKeyPair keyPair, X509Certificate certificate, SecureRandom random)
    {
        string dir = Path.Combine(testDataRoot, relativeDir.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, fileName);

        var content = new CmsProcessableByteArray(
            Encoding.UTF8.GetBytes("CodeBrix.Cryptography sample CMS SignedData signed with " + algorithm + "."));

        var generator = new CmsSignedDataGenerator();
        // ML-DSA is not one of the hash-then-sign mechanisms CmsSignedHelper can resolve
        // an encryption OID for, so the signature factory is supplied directly.
        var signatureFactory = new Asn1SignatureFactory(algorithm, keyPair.Private, random);
        generator.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().Build(signatureFactory, certificate));
        generator.AddCertificates(CollectionUtilities.CreateStore(new[] { certificate }));

        CmsSignedData signedData = generator.Generate(content, encapsulate: true);

        using (var writer = new StreamWriter(path))
        using (var pemWriter = new PemWriter(writer))
        {
            pemWriter.WriteObject(new PemObject("CMS", signedData.GetEncoded()));
        }

        return path;
    }

    private static AsymmetricCipherKeyPair GenerateMLDsa(MLDsaParameters parameters, SecureRandom random)
    {
        var generator = new MLDsaKeyPairGenerator();
        generator.Init(new MLDsaKeyGenerationParameters(random, parameters));
        return generator.GenerateKeyPair();
    }

    private static X509Certificate IssueCertificate(X509Name subject, AsymmetricKeyParameter subjectPublicKey,
        X509Name issuer, ISignatureFactory signatureFactory, SecureRandom random)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigIntegers.CreateRandomInRange(BigInteger.One,
            BigInteger.One.ShiftLeft(120), random));
        generator.SetIssuerDN(issuer);
        generator.SetSubjectDN(subject);
        // A fixed validity window keeps regeneration reproducible in everything but the
        // key material, and far enough out that the fixtures do not expire.
        generator.SetNotBefore(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        generator.SetNotAfter(new DateTime(2126, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        generator.SetPublicKey(subjectPublicKey);
        return generator.Generate(signatureFactory);
    }

    /// <summary>
    /// Writes the PRIVATE KEY, PUBLIC KEY and CERTIFICATE blocks, in the order
    /// SampleCredentials.Load expects them.
    /// </summary>
    private static string WriteCredentials(string testDataRoot, string relativeDir, string fileName,
        AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
    {
        string dir = Path.Combine(testDataRoot, relativeDir.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, fileName);

        var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
        var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);

        using (var writer = new StreamWriter(path))
        using (var pemWriter = new PemWriter(writer))
        {
            pemWriter.WriteObject(new PemObject("PRIVATE KEY", privateKeyInfo.GetEncoded()));
            pemWriter.WriteObject(new PemObject("PUBLIC KEY", spki.GetEncoded()));
            pemWriter.WriteObject(new PemObject("CERTIFICATE", certificate.GetEncoded()));
        }

        return path;
    }
}
