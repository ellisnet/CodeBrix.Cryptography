using System;
using System.Collections.Generic;
using System.IO;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Pkcs;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Asn1.X9;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Digests;
using CodeBrix.Cryptography.Crypto.Generators;
using CodeBrix.Cryptography.Crypto.Operators;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Math;
using CodeBrix.Cryptography.Pkcs;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.IO.Pem;
using CodeBrix.Cryptography.X509;
using Xunit;

namespace CodeBrix.Cryptography.TestDataGeneration;

/// <summary>
/// Regenerates the TLS/DTLS credentials under test-data/tls/credentials/.
/// </summary>
/// <remarks>
/// Upstream loads these from the separate, unlicensed bc-test-data repository. This fork
/// generates equivalents with this library instead, so the fixtures are ours to
/// redistribute under the repository's MIT licence.
///
/// The certificates only have to be internally consistent: the TLS harness compares the
/// certificate a peer presented against the same file it loaded, and validates the chain
/// against our own CA. Nothing depends on the upstream key material. The extension shape
/// (basic constraints, key usage, extended key usage, subject/authority key identifiers)
/// mirrors what the TLS code paths expect of a real credential.
/// </remarks>
public class TlsCredentialGenerator
{
    public static bool IsGenerationRequested =>
        Environment.GetEnvironmentVariable("CODEBRIX_CRYPTOGRAPHY_REGENERATE_TEST_DATA") == "1";

    private const long MaxFileBytes = 50L * 1024 * 1024;

    private static readonly X509Name CaName = new X509Name("CN=CodeBrix.Cryptography TLS Test CA");
    private static readonly X509Name ServerName = new X509Name("CN=CodeBrix.Cryptography Test Server");
    private static readonly X509Name ClientName = new X509Name("CN=CodeBrix.Cryptography Test Client");

    // The rsa_pss_* families are the awkward ones: an rsa_pss_pss_* credential must carry
    // an id-RSASSA-PSS SubjectPublicKeyInfo, but X509V3CertificateGenerator.SetPublicKey
    // takes a key and derives a plain rsaEncryption SubjectPublicKeyInfo from it. Those
    // certificates are therefore assembled through V3TbsCertificateGenerator instead --
    // see IssuePssCertificate.
    private static readonly (string Name, string KeyKind, string SignatureAlgorithm)[] Families =
    {
        ("rsa", "rsa", "SHA256withRSA"),
        ("dsa", "dsa", "SHA256withDSA"),
        ("ecdsa", "ec", "SHA256withECDSA"),
        ("ed25519", "ed25519", "Ed25519"),
        ("ed448", "ed448", "Ed448"),
        ("ml_dsa_44", "ml_dsa_44", "ML-DSA-44"),
        ("ml_dsa_65", "ml_dsa_65", "ML-DSA-65"),
        ("ml_dsa_87", "ml_dsa_87", "ML-DSA-87"),
        ("rsa_pss_256", "rsa", "SHA256withRSAandMGF1"),
        ("rsa_pss_384", "rsa", "SHA384withRSAandMGF1"),
        ("rsa_pss_512", "rsa", "SHA512withRSAandMGF1"),
        ("slh_dsa_sha2_128s", "slh_dsa_sha2_128s", "SLH-DSA-SHA2-128S"),
        ("slh_dsa_sha2_128f", "slh_dsa_sha2_128f", "SLH-DSA-SHA2-128F"),
        ("slh_dsa_sha2_192s", "slh_dsa_sha2_192s", "SLH-DSA-SHA2-192S"),
        ("slh_dsa_sha2_192f", "slh_dsa_sha2_192f", "SLH-DSA-SHA2-192F"),
        ("slh_dsa_sha2_256s", "slh_dsa_sha2_256s", "SLH-DSA-SHA2-256S"),
        ("slh_dsa_sha2_256f", "slh_dsa_sha2_256f", "SLH-DSA-SHA2-256F"),
        ("slh_dsa_shake_128s", "slh_dsa_shake_128s", "SLH-DSA-SHAKE-128S"),
        ("slh_dsa_shake_128f", "slh_dsa_shake_128f", "SLH-DSA-SHAKE-128F"),
        ("slh_dsa_shake_192s", "slh_dsa_shake_192s", "SLH-DSA-SHAKE-192S"),
        ("slh_dsa_shake_192f", "slh_dsa_shake_192f", "SLH-DSA-SHAKE-192F"),
        ("slh_dsa_shake_256s", "slh_dsa_shake_256s", "SLH-DSA-SHAKE-256S"),
        ("slh_dsa_shake_256f", "slh_dsa_shake_256f", "SLH-DSA-SHAKE-256F"),
        // Upstream has no test resources for these schemes (its FindResourceName13
        // returns null and marks them TODO), so BcTlsCryptoTest.TestSignatures13 never
        // exercised them. This fork generates the credentials and maps the schemes, so
        // the brainpool, secp384/521 and SM2 signature paths are covered too.
        ("brainpoolP256r1", "ec:brainpoolP256r1", "SHA256withECDSA"),
        ("brainpoolP384r1", "ec:brainpoolP384r1", "SHA384withECDSA"),
        ("brainpoolP512r1", "ec:brainpoolP512r1", "SHA512withECDSA"),
        ("secp384r1", "ec:secp384r1", "SHA384withECDSA"),
        ("secp521r1", "ec:secp521r1", "SHA512withECDSA"),
        ("sm2", "ec:sm2p256v1", "SM3withSM2"),
    };

    private static bool IsPss(string familyName) => familyName.StartsWith("rsa_pss_");

    // Role, resource name, issuing CA family, key kind, key usage bits.
    private static readonly (string Role, string Name, string Ca, string KeyKind, int KeyUsageBits)[] EndEntities =
    {
        ("client", "dsa", "dsa", "dsa", KeyUsage.DigitalSignature),
        ("server", "dsa", "dsa", "dsa", KeyUsage.DigitalSignature),
        ("client", "ecdsa", "ecdsa", "ec", KeyUsage.DigitalSignature),
        ("server", "ecdsa", "ecdsa", "ec", KeyUsage.DigitalSignature),
        ("client", "ecdh", "ecdsa", "ec", KeyUsage.DigitalSignature | KeyUsage.KeyAgreement),
        ("server", "ecdh", "ecdsa", "ec", KeyUsage.DigitalSignature | KeyUsage.KeyAgreement),
        ("client", "ed25519", "ed25519", "ed25519", KeyUsage.DigitalSignature),
        ("server", "ed25519", "ed25519", "ed25519", KeyUsage.DigitalSignature),
        ("client", "ed448", "ed448", "ed448", KeyUsage.DigitalSignature),
        ("server", "ed448", "ed448", "ed448", KeyUsage.DigitalSignature),
        ("client", "rsa", "rsa", "rsa", KeyUsage.DigitalSignature),
        ("server", "rsa-sign", "rsa", "rsa", KeyUsage.DigitalSignature),
        ("server", "rsa-enc", "rsa", "rsa", KeyUsage.KeyEncipherment),
        ("client", "ml_dsa_44", "ml_dsa_44", "ml_dsa_44", KeyUsage.DigitalSignature),
        ("server", "ml_dsa_44", "ml_dsa_44", "ml_dsa_44", KeyUsage.DigitalSignature),
        ("client", "ml_dsa_65", "ml_dsa_65", "ml_dsa_65", KeyUsage.DigitalSignature),
        ("server", "ml_dsa_65", "ml_dsa_65", "ml_dsa_65", KeyUsage.DigitalSignature),
        ("client", "ml_dsa_87", "ml_dsa_87", "ml_dsa_87", KeyUsage.DigitalSignature),
        ("server", "ml_dsa_87", "ml_dsa_87", "ml_dsa_87", KeyUsage.DigitalSignature),
        ("client", "rsa_pss_256", "rsa_pss_256", "rsa", KeyUsage.DigitalSignature),
        ("server", "rsa_pss_256", "rsa_pss_256", "rsa", KeyUsage.DigitalSignature),
        ("client", "rsa_pss_384", "rsa_pss_384", "rsa", KeyUsage.DigitalSignature),
        ("server", "rsa_pss_384", "rsa_pss_384", "rsa", KeyUsage.DigitalSignature),
        ("client", "rsa_pss_512", "rsa_pss_512", "rsa", KeyUsage.DigitalSignature),
        ("server", "rsa_pss_512", "rsa_pss_512", "rsa", KeyUsage.DigitalSignature),
        ("client", "slh_dsa_sha2_128s", "slh_dsa_sha2_128s", "slh_dsa_sha2_128s", KeyUsage.DigitalSignature),
        ("server", "slh_dsa_sha2_128s", "slh_dsa_sha2_128s", "slh_dsa_sha2_128s", KeyUsage.DigitalSignature),
        ("client", "slh_dsa_sha2_128f", "slh_dsa_sha2_128f", "slh_dsa_sha2_128f", KeyUsage.DigitalSignature),
        ("server", "slh_dsa_sha2_128f", "slh_dsa_sha2_128f", "slh_dsa_sha2_128f", KeyUsage.DigitalSignature),
        ("client", "slh_dsa_sha2_192s", "slh_dsa_sha2_192s", "slh_dsa_sha2_192s", KeyUsage.DigitalSignature),
        ("server", "slh_dsa_sha2_192s", "slh_dsa_sha2_192s", "slh_dsa_sha2_192s", KeyUsage.DigitalSignature),
        ("client", "slh_dsa_sha2_192f", "slh_dsa_sha2_192f", "slh_dsa_sha2_192f", KeyUsage.DigitalSignature),
        ("server", "slh_dsa_sha2_192f", "slh_dsa_sha2_192f", "slh_dsa_sha2_192f", KeyUsage.DigitalSignature),
        ("client", "slh_dsa_sha2_256s", "slh_dsa_sha2_256s", "slh_dsa_sha2_256s", KeyUsage.DigitalSignature),
        ("server", "slh_dsa_sha2_256s", "slh_dsa_sha2_256s", "slh_dsa_sha2_256s", KeyUsage.DigitalSignature),
        ("client", "slh_dsa_sha2_256f", "slh_dsa_sha2_256f", "slh_dsa_sha2_256f", KeyUsage.DigitalSignature),
        ("server", "slh_dsa_sha2_256f", "slh_dsa_sha2_256f", "slh_dsa_sha2_256f", KeyUsage.DigitalSignature),
        ("client", "slh_dsa_shake_128s", "slh_dsa_shake_128s", "slh_dsa_shake_128s", KeyUsage.DigitalSignature),
        ("server", "slh_dsa_shake_128s", "slh_dsa_shake_128s", "slh_dsa_shake_128s", KeyUsage.DigitalSignature),
        ("client", "slh_dsa_shake_128f", "slh_dsa_shake_128f", "slh_dsa_shake_128f", KeyUsage.DigitalSignature),
        ("server", "slh_dsa_shake_128f", "slh_dsa_shake_128f", "slh_dsa_shake_128f", KeyUsage.DigitalSignature),
        ("client", "slh_dsa_shake_192s", "slh_dsa_shake_192s", "slh_dsa_shake_192s", KeyUsage.DigitalSignature),
        ("server", "slh_dsa_shake_192s", "slh_dsa_shake_192s", "slh_dsa_shake_192s", KeyUsage.DigitalSignature),
        ("client", "slh_dsa_shake_192f", "slh_dsa_shake_192f", "slh_dsa_shake_192f", KeyUsage.DigitalSignature),
        ("server", "slh_dsa_shake_192f", "slh_dsa_shake_192f", "slh_dsa_shake_192f", KeyUsage.DigitalSignature),
        ("client", "slh_dsa_shake_256s", "slh_dsa_shake_256s", "slh_dsa_shake_256s", KeyUsage.DigitalSignature),
        ("server", "slh_dsa_shake_256s", "slh_dsa_shake_256s", "slh_dsa_shake_256s", KeyUsage.DigitalSignature),
        ("client", "slh_dsa_shake_256f", "slh_dsa_shake_256f", "slh_dsa_shake_256f", KeyUsage.DigitalSignature),
        ("server", "slh_dsa_shake_256f", "slh_dsa_shake_256f", "slh_dsa_shake_256f", KeyUsage.DigitalSignature),
        ("client", "brainpoolP256r1", "brainpoolP256r1", "ec:brainpoolP256r1", KeyUsage.DigitalSignature),
        ("server", "brainpoolP256r1", "brainpoolP256r1", "ec:brainpoolP256r1", KeyUsage.DigitalSignature),
        ("client", "brainpoolP384r1", "brainpoolP384r1", "ec:brainpoolP384r1", KeyUsage.DigitalSignature),
        ("server", "brainpoolP384r1", "brainpoolP384r1", "ec:brainpoolP384r1", KeyUsage.DigitalSignature),
        ("client", "brainpoolP512r1", "brainpoolP512r1", "ec:brainpoolP512r1", KeyUsage.DigitalSignature),
        ("server", "brainpoolP512r1", "brainpoolP512r1", "ec:brainpoolP512r1", KeyUsage.DigitalSignature),
        ("client", "secp384r1", "secp384r1", "ec:secp384r1", KeyUsage.DigitalSignature),
        ("server", "secp384r1", "secp384r1", "ec:secp384r1", KeyUsage.DigitalSignature),
        ("client", "secp521r1", "secp521r1", "ec:secp521r1", KeyUsage.DigitalSignature),
        ("server", "secp521r1", "secp521r1", "ec:secp521r1", KeyUsage.DigitalSignature),
        ("client", "sm2", "sm2", "ec:sm2p256v1", KeyUsage.DigitalSignature),
        ("server", "sm2", "sm2", "ec:sm2p256v1", KeyUsage.DigitalSignature),
    };

    [Fact(Skip = "Utility: regenerates test-data/tls/credentials. Set " +
                 "CODEBRIX_CRYPTOGRAPHY_REGENERATE_TEST_DATA=1 to run it.",
          SkipUnless = nameof(IsGenerationRequested))]
    public void RegenerateTlsCredentials()
    {
        string dir = Path.Combine(TestDataPaths.RepositoryTestDataRoot(), "tls", "credentials");
        Directory.CreateDirectory(dir);

        var random = new SecureRandom();
        var written = new List<string>();
        var cas = new Dictionary<string, (AsymmetricCipherKeyPair KeyPair, X509Certificate Certificate,
            string SignatureAlgorithm)>();

        foreach (var family in Families)
        {
            var keyPair = GenerateKeyPair(family.KeyKind, random);
            var signatureFactory = new Asn1SignatureFactory(family.SignatureAlgorithm, keyPair.Private, random);

            var extensions = new X509ExtensionsGenerator();
            extensions.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(true));
            extensions.AddExtension(X509Extensions.KeyUsage, critical: true,
                new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
            extensions.AddExtension(X509Extensions.SubjectKeyIdentifier, critical: false,
                CreateSubjectKeyIdentifier(keyPair.Public, IsPss(family.Name), signatureFactory));

            var certificate = IssueCertificate(CaName, CaName, keyPair.Public, extensions, signatureFactory,
                IsPss(family.Name), random);
            cas[family.Name] = (keyPair, certificate, family.SignatureAlgorithm);

            written.Add(WritePem(dir, "x509-ca-" + family.Name + ".pem", "CERTIFICATE", certificate.GetEncoded()));
            written.Add(WritePem(dir, "x509-ca-key-" + family.Name + ".pem", "PRIVATE KEY",
                PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private).GetEncoded()));
        }

        foreach (var ee in EndEntities)
        {
            var ca = cas[ee.Ca];
            var keyPair = GenerateKeyPair(ee.KeyKind, random);
            bool forServer = ee.Role == "server";

            bool eePss = IsPss(ee.Name);
            var caFactory = new Asn1SignatureFactory(ca.SignatureAlgorithm, ca.KeyPair.Private, random);

            var extensions = new X509ExtensionsGenerator();
            extensions.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(false));
            extensions.AddExtension(X509Extensions.KeyUsage, critical: true, new KeyUsage(ee.KeyUsageBits));
            extensions.AddExtension(X509Extensions.ExtendedKeyUsage, critical: false,
                new ExtendedKeyUsage(forServer ? KeyPurposeID.id_kp_serverAuth : KeyPurposeID.id_kp_clientAuth));
            extensions.AddExtension(X509Extensions.SubjectKeyIdentifier, critical: false,
                CreateSubjectKeyIdentifier(keyPair.Public, eePss, caFactory));
            extensions.AddExtension(X509Extensions.AuthorityKeyIdentifier, critical: false,
                new AuthorityKeyIdentifier(BuildSubjectPublicKeyInfo(ca.KeyPair.Public, IsPss(ee.Ca), caFactory)));

            var certificate = IssueCertificate(forServer ? ServerName : ClientName, CaName, keyPair.Public,
                extensions, caFactory, eePss, random);

            string prefix = "x509-" + ee.Role + "-";
            written.Add(WritePem(dir, prefix + ee.Name + ".pem", "CERTIFICATE", certificate.GetEncoded()));
            written.Add(WritePem(dir, prefix + "key-" + ee.Name + ".pem", "PRIVATE KEY",
                PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private).GetEncoded()));
        }

        foreach (string path in written)
        {
            Assert.True(new FileInfo(path).Length <= MaxFileBytes, path + " exceeds the 50 MB file limit");
        }
        Assert.Equal((Families.Length + EndEntities.Length) * 2, written.Count);
    }

    /// <summary>
    /// Builds the certificate at the TBS level so that PSS credentials can carry an
    /// id-RSASSA-PSS SubjectPublicKeyInfo, which X509V3CertificateGenerator cannot express.
    /// </summary>
    private static X509Certificate IssueCertificate(X509Name subject, X509Name issuer,
        AsymmetricKeyParameter subjectPublicKey, X509ExtensionsGenerator extensions,
        ISignatureFactory signatureFactory, bool subjectIsPss, SecureRandom random)
    {
        var signatureAlgorithm = (AlgorithmIdentifier)signatureFactory.AlgorithmDetails;

        var tbsGenerator = new V3TbsCertificateGenerator();
        tbsGenerator.SetSerialNumber(new DerInteger(BigIntegers.CreateRandomInRange(BigInteger.One,
            BigInteger.One.ShiftLeft(120), random)));
        tbsGenerator.SetIssuer(issuer);
        tbsGenerator.SetSubject(subject);
        tbsGenerator.SetStartDate(new Time(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)));
        tbsGenerator.SetEndDate(new Time(new DateTime(2126, 1, 1, 0, 0, 0, DateTimeKind.Utc)));
        tbsGenerator.SetSubjectPublicKeyInfo(
            BuildSubjectPublicKeyInfo(subjectPublicKey, subjectIsPss, signatureFactory));
        tbsGenerator.SetSignature(signatureAlgorithm);
        tbsGenerator.SetExtensions(extensions.Generate());

        var tbsCertificate = tbsGenerator.GenerateTbsCertificate();
        var signature = CodeBrix.Cryptography.X509.X509Utilities.GenerateSignature(
            signatureFactory, tbsCertificate);
        return new X509Certificate(new X509CertificateStructure(tbsCertificate, signatureAlgorithm, signature));
    }

    /// <summary>
    /// For a PSS credential the SubjectPublicKeyInfo has to name id-RSASSA-PSS with the
    /// same parameters the signature algorithm uses, rather than plain rsaEncryption.
    /// Those parameters are taken from the signature factory so the two always agree.
    /// </summary>
    private static SubjectPublicKeyInfo BuildSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey,
        bool isPss, ISignatureFactory pssSignatureFactory)
    {
        if (!isPss)
            return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);

        var rsa = (RsaKeyParameters)publicKey;
        var pssAlgorithm = (AlgorithmIdentifier)pssSignatureFactory.AlgorithmDetails;
        return new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(PkcsObjectIdentifiers.IdRsassaPss, pssAlgorithm.Parameters),
            new RsaPublicKeyStructure(rsa.Modulus, rsa.Exponent));
    }

    private static SubjectKeyIdentifier CreateSubjectKeyIdentifier(AsymmetricKeyParameter publicKey,
        bool isPss, ISignatureFactory pssSignatureFactory) =>
        new SubjectKeyIdentifier(BuildSubjectPublicKeyInfo(publicKey, isPss, pssSignatureFactory));

    private static AsymmetricCipherKeyPair GenerateKeyPair(string keyKind, SecureRandom random)
    {
        switch (keyKind)
        {
        case "rsa":
        {
            var generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(random, 2048));
            return generator.GenerateKeyPair();
        }
        case "dsa":
        {
            // N=256 needs a digest of at least 256 bits; the parameterless
            // constructor uses SHA-1, which is why FIPS 186-3 generation rejects it.
            var parametersGenerator = new DsaParametersGenerator(new Sha256Digest());
            // 2048-bit DSA parameter generation is slow; this utility runs rarely and the
            // TLS 1.2 DSA credentials need a realistic key size.
            parametersGenerator.Init(new DsaParameterGenerationParameters(2048, 256, 80, random));
            var generator = new DsaKeyPairGenerator();
            generator.Init(new DsaKeyGenerationParameters(random, parametersGenerator.GenerateParameters()));
            return generator.GenerateKeyPair();
        }
        case "ec":
            return GenerateEC("prime256v1", random);
        case "ed25519":
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(random));
            return generator.GenerateKeyPair();
        }
        case "ed448":
        {
            var generator = new Ed448KeyPairGenerator();
            generator.Init(new Ed448KeyGenerationParameters(random));
            return generator.GenerateKeyPair();
        }
        case "ml_dsa_44":
            return GenerateMLDsa(MLDsaParameters.ml_dsa_44, random);
        case "ml_dsa_65":
            return GenerateMLDsa(MLDsaParameters.ml_dsa_65, random);
        case "ml_dsa_87":
            return GenerateMLDsa(MLDsaParameters.ml_dsa_87, random);
        default:
            // Named-curve EC families carry their curve in the key kind, e.g. "ec:secp384r1".
            if (keyKind.StartsWith("ec:"))
                return GenerateEC(keyKind.Substring("ec:".Length), random);

            // Every SLH-DSA parameter set shares one code path, keyed by name.
            if (keyKind.StartsWith("slh_dsa_"))
            {
                var parameters = SlhDsaParameters.ByName[SlhDsaAlgorithmName(keyKind)];
                var generator = new SlhDsaKeyPairGenerator();
                generator.Init(new SlhDsaKeyGenerationParameters(random, parameters));
                return generator.GenerateKeyPair();
            }
            throw new InvalidOperationException("Unknown key kind: " + keyKind);
        }
    }

    private static AsymmetricCipherKeyPair GenerateEC(string curveName, SecureRandom random)
    {
        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(ECNamedCurveTable.GetOid(curveName), random));
        return generator.GenerateKeyPair();
    }

    /// <summary>Maps "slh_dsa_sha2_128s" to the registered name "SLH-DSA-SHA2-128S".</summary>
    private static string SlhDsaAlgorithmName(string keyKind)
    {
        string[] parts = keyKind.Substring("slh_dsa_".Length).Split('_');
        return "SLH-DSA-" + parts[0].ToUpperInvariant() + "-" + parts[1].ToUpperInvariant();
    }

    private static AsymmetricCipherKeyPair GenerateMLDsa(MLDsaParameters parameters, SecureRandom random)
    {
        var generator = new MLDsaKeyPairGenerator();
        generator.Init(new MLDsaKeyGenerationParameters(random, parameters));
        return generator.GenerateKeyPair();
    }

    private static string WritePem(string dir, string fileName, string type, byte[] content)
    {
        string path = Path.Combine(dir, fileName);
        using (var writer = new StreamWriter(path))
        using (var pemWriter = new PemWriter(writer))
        {
            pemWriter.WriteObject(new PemObject(type, content));
        }
        return path;
    }
}
