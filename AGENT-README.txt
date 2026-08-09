================================================================================
AGENT-README: CodeBrix.Cryptography
A Comprehensive Guide for AI Coding Agents
================================================================================


OVERVIEW
--------------------------------------------------------------------------------

CodeBrix.Cryptography is a fully managed, cross-platform, general-purpose
cryptography library for .NET 10. It covers ASN.1 encoding, a very broad set of
symmetric and asymmetric ciphers, digests, MACs, signatures and key agreement,
post-quantum algorithms, TLS and DTLS, OpenPGP, CMS/S-MIME, PKCS, CMP, CRMF,
OCSP, TSP, X.509 certificate and CRL handling and path validation, and OpenSSL
PEM interoperability.

CodeBrix.Cryptography is a fork of BouncyCastle.NET 2.7.0
(https://github.com/bcgit/bc-csharp), narrowed to net10.0 and rehomed under the
CodeBrix.Cryptography namespace. Every public type keeps its BouncyCastle name,
member names and signatures, so the library is a drop-in replacement for the
BouncyCastle.Cryptography NuGet package: migrating a consumer is a package swap
plus a find-and-replace of "Org.BouncyCastle" with "CodeBrix.Cryptography".

Because the public API is BouncyCastle's, the BouncyCastle documentation and
the very large body of BouncyCastle sample code on the web apply verbatim once
the namespace prefix is adjusted. When you need to know how a type behaves,
that is the reference to use.


POST-QUANTUM ALGORITHMS ARE EXPERIMENTAL
--------------------------------------------------------------------------------

Upstream BouncyCastle.NET states that its NIST Post-Quantum Cryptography
Standardization implementations "should all be considered EXPERIMENTAL and
subject to change or removal", and that carries over to this fork unchanged --
the code is the same code.

That covers everything under CodeBrix.Cryptography.Pqc, plus the ML-KEM, ML-DSA
and SLH-DSA support in CodeBrix.Cryptography.Crypto. Treat their APIs, parameter
sets and encodings as unstable across releases. In particular, do not use them to
protect data that has to remain readable after an upgrade, and do not assume a
key or signature produced by one version will be parseable by the next.

The classical algorithms carry no such caveat.


INSTALLATION
--------------------------------------------------------------------------------

NuGet package:  CodeBrix.Cryptography.MitLicenseForever

    dotnet add package CodeBrix.Cryptography.MitLicenseForever

Note that the ".MitLicenseForever" suffix is part of the PACKAGE ID only. The
assembly, the root namespace and every type live under "CodeBrix.Cryptography"
without the suffix.

Target framework: .NET 10.0 or higher. There is no multi-targeting; net10.0 is
the only supported target, and netstandard / .NET Framework are not supported.

NuGet dependencies: none. The library depends only on the .NET base class
library.


KEY NAMESPACES
--------------------------------------------------------------------------------

There is no single entry-point type; the library is a large toolbox, organised
the same way BouncyCastle organises it. The top-level namespaces are:

  CodeBrix.Cryptography.Asn1          ASN.1 objects, DER/BER/DL encoding, and
                                      the OID and structure definitions for
                                      X.509, PKCS, CMS, CMP, CRMF, OCSP, TSP,
                                      X9.62, NIST, SEC and many other specs.
                                      Sub-namespaces mirror the specifications.

  CodeBrix.Cryptography.Crypto        The algorithm layer: Engines (block and
                                      stream ciphers), Modes, Paddings, Digests,
                                      Macs, Signers, Generators, Agreement,
                                      Parameters, Prng, Kems, Encodings, Tls,
                                      Fpe, Operators and Utilities.

  CodeBrix.Cryptography.Math          BigInteger, elliptic-curve arithmetic
                                      (EC, EC.Custom.Sec, EC.Rfc7748,
                                      EC.Rfc8032, EC.Endo, EC.Multiplier),
                                      field arithmetic and BinPoly.

  CodeBrix.Cryptography.Security      The high-level "factory" facade:
                                      SecureRandom, DigestUtilities,
                                      CipherUtilities, SignerUtilities,
                                      MacUtilities, GeneratorUtilities,
                                      ParameterUtilities, PrivateKeyFactory,
                                      PublicKeyFactory, DotNetUtilities.

  CodeBrix.Cryptography.X509          X509Certificate, X509Crl,
                                      X509V1/V2/V3 generators, certificate and
                                      CRL parsers, and the store abstractions.

  CodeBrix.Cryptography.Pkix          PKIX certificate path building and
                                      validation.

  CodeBrix.Cryptography.Pkcs          PKCS#7/#8/#10/#12 - Pkcs12Store,
                                      Pkcs10CertificationRequest,
                                      PrivateKeyInfoFactory and friends.

  CodeBrix.Cryptography.Cms           CMS / S-MIME: signed, enveloped, digested,
                                      encrypted and compressed data.

  CodeBrix.Cryptography.Tls           TLS 1.0-1.3 and DTLS 1.0-1.2 client and
                                      server, with Tls.Crypto and
                                      Tls.Crypto.Impl.BC as the pluggable
                                      crypto layer.

  CodeBrix.Cryptography.Bcpg          OpenPGP: Bcpg is the packet layer and
                                      Bcpg.OpenPgp is the high-level API
                                      (PgpSecretKeyRing, PgpEncryptedDataGenerator,
                                      PgpSignatureGenerator, ArmoredOutputStream).

  CodeBrix.Cryptography.Pqc           Post-quantum: Crypto.Crystals.Dilithium,
                                      Crypto.Crystals.Kyber, Crypto.SphincsPlus,
                                      Crypto.Lms, Crypto.Falcon, Crypto.Bike,
                                      Crypto.Hqc, Crypto.Cmce, Crypto.Frodo,
                                      Crypto.NtruPrime, Crypto.Picnic,
                                      Crypto.Saber, Crypto.Snova, and the Asn1
                                      and Crypto.Utilities helpers.

  CodeBrix.Cryptography.Cmp           CMP (RFC 4210) message handling.
  CodeBrix.Cryptography.Crmf          CRMF (RFC 4211) certificate requests.
  CodeBrix.Cryptography.Ocsp          OCSP request and response handling.
  CodeBrix.Cryptography.Tsp           RFC 3161 timestamping.
  CodeBrix.Cryptography.OpenSsl       PEM reading and writing.
  CodeBrix.Cryptography.Operators     Signature and verifier factories.
  CodeBrix.Cryptography.Mozilla       SignedPublicKeyAndChallenge.
  CodeBrix.Cryptography.Runtime       Runtime.Intrinsics.X86 CPU feature gates.
  CodeBrix.Cryptography.Utilities     Arrays, BigIntegers, Encoders (Hex,
                                      Base64, UrlBase64), IO (Streams, Pem),
                                      Collections, Date, Zlib, Bzip2 and the
                                      Properties configuration accessor.


CORE API REFERENCE
--------------------------------------------------------------------------------

The public surface is BouncyCastle 2.7.0's, unchanged. Rather than restate
thousands of members, here are the shapes an agent needs most often.

Randomness

    var random = new SecureRandom();          // CodeBrix.Cryptography.Security
    random.NextBytes(buffer);

  SecureRandom is the source every generator in the library expects. Prefer it
  over System.Random, and reuse one instance.

AEAD encryption (the usual choice for "encrypt this")

    var cipher = new GcmBlockCipher(AesUtilities.CreateEngine());
    cipher.Init(forEncryption: true,
        new AeadParameters(new KeyParameter(key), macSizeBits, nonce, associatedData));
    int n = cipher.ProcessBytes(input, 0, input.Length, output, 0);
    n += cipher.DoFinal(output, n);

  Allocate `output` with cipher.GetOutputSize(input.Length). On decryption,
  DoFinal throws InvalidCipherTextException when the tag does not verify -- that
  exception IS the authentication failure, so never ignore it. GcmBlockCipher,
  CcmBlockCipher, EaxBlockCipher, OcbBlockCipher and ChaCha20Poly1305 all
  implement IAeadCipher and follow this same Init/ProcessBytes/DoFinal shape.

Digests and MACs

    IDigest digest = new Sha256Digest();
    digest.BlockUpdate(data, 0, data.Length);
    byte[] hash = new byte[digest.GetDigestSize()];
    digest.DoFinal(hash, 0);

    IMac mac = new HMac(new Sha256Digest());
    mac.Init(new KeyParameter(key));

  DigestUtilities.GetDigest("SHA-256") and MacUtilities.GetMac("HMACSHA256")
  resolve by name or OID when the algorithm is chosen at runtime.

Asymmetric keys

    var generator = new RsaKeyPairGenerator();
    generator.Init(new KeyGenerationParameters(random, 2048));
    AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();

  GeneratorUtilities.GetKeyPairGenerator("ECDSA") and friends resolve by name.
  PrivateKeyFactory / PublicKeyFactory convert to and from PKCS#8 and
  SubjectPublicKeyInfo encodings; PrivateKeyInfoFactory and
  SubjectPublicKeyInfoFactory go the other way.

Signatures

    ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");
    signer.Init(forSigning: true, pair.Private);
    signer.BlockUpdate(data, 0, data.Length);
    byte[] signature = signer.GenerateSignature();

  Verification uses the same type with forSigning: false and VerifySignature.

Certificates

    var gen = new X509V3CertificateGenerator();
    // SetSerialNumber / SetIssuerDN / SetSubjectDN / SetNotBefore /
    // SetNotAfter / SetPublicKey / AddExtension
    X509Certificate cert = gen.Generate(
        new Asn1SignatureFactory("SHA256WITHRSA", pair.Private, random));

  X509CertificateParser reads DER or PEM; cert.Verify(publicKey) and
  cert.CheckValidity() are the two checks you almost always want.

ASN.1

  Asn1Object.FromByteArray / Asn1Sequence.GetInstance / DerInteger / DerOctetString
  and the per-specification structure classes under
  CodeBrix.Cryptography.Asn1.* . GetEncoded("DER") produces DER; GetEncoded()
  produces BER.

Error model

  There is no single exception base. The library throws
  CryptoException/InvalidCipherTextException (algorithm layer),
  Asn1Exception/Asn1ParsingException (encoding), SecurityUtilityException and
  GeneralSecurityException (Security facade), CmsException, PkcsException,
  PgpException, TlsFatalAlert, OcspException, TspException,
  CertificateEncodingException and CrlException, plus the ordinary
  ArgumentException / InvalidOperationException / IOException for misuse.

Runtime configuration

  A small number of limits are read from environment variables at runtime
  through CodeBrix.Cryptography.Utilities.Properties. IMPORTANT: those keys keep
  their upstream spelling -- "Org.BouncyCastle.Asn1.MaxDepth",
  "Org.BouncyCastle.Pkcs12.MaxIterationCount", "Org.BouncyCastle.Rsa.MaxSize"
  and so on -- deliberately, so that an application already configured for the
  BouncyCastle.Cryptography package keeps working unchanged after swapping in
  this one. Do NOT "fix" these strings to say CodeBrix; that would be a breaking
  change for consumers. They are the only remaining occurrences of the string
  "Org.BouncyCastle" outside the per-file provenance comments.


CODING CONVENTIONS (CodeBrix family)
--------------------------------------------------------------------------------

These rules apply to every change made to this repository.

  * Target framework is net10.0 only. Do not add target frameworks and do not
    reintroduce framework-selection #if directives. The port already evaluated
    every one of them for net10.0 and deleted the dead branches.

  * Nullable reference types are OFF. Never write `?` on a reference type
    (`string?`, `MyClass?`, `object?`) and never use the null-forgiveness `!`
    operator. Value-type nullables (`int?`, `bool?`, `DateTime?`) are fine.
    Do not add `#nullable` directives or a <Nullable> csproj property.

  * No implicit usings and no `global using`. Every file declares the usings
    it needs.

  * File-scoped namespaces only (`namespace X;`), never block-scoped.

  * Usings sit above the namespace in a single contiguous block with no blank
    lines inside it: System.* first, then everything else, alphabetical within
    each group, with aliases last.

  * Every file ported from BouncyCastle.NET carries a provenance comment on its
    namespace line:

        namespace CodeBrix.Cryptography.Crypto.Digests;
            //was previously: Org.BouncyCastle.Crypto.Digests;

    Keep it when editing a ported file. New-in-fork files do not get one.

  * The build must be 0 warnings / 0 errors, in Debug and in Release. Do not
    add <NoWarn>, <WarningLevel>, or #pragma warning disable to silence
    anything beyond the two exceptions already documented below.

  * DOCUMENTED EXCEPTION 1 -- CS1591 in the library project.
    <GenerateDocumentationFile> is true, but <NoWarn>1591</NoWarn> is set,
    because the ported BouncyCastle surface is thousands of public members with
    no upstream XML doc comments; upstream builds with the same suppression.
    This is the same situational exception already taken by
    CodeBrix.Platform.OpenGL and CodeBrix.AssemblyTools. When you ADD a new
    public member, still write an XML doc comment for it.

  * DOCUMENTED EXCEPTION 2 -- CS0618 in the test project.
    A cryptography suite has to keep testing algorithms the library has
    deprecated but still ships, so the test project sets <NoWarn>618</NoWarn>.
    Upstream does the same. This applies to test code only, never to the
    library.

  * Two `#pragma warning disable CA1857` regions exist, in
    Crypto/Engines/AesEngine_X86.cs and Crypto/Engines/Salsa20Engine.cs, where
    hand-tuned intrinsics pass loop-carried values to parameters declared
    [ConstantExpected]. Each carries a comment explaining why. Do not add more
    pragmas without the same kind of justification.

  * The formatter-based serialization constructors and GetObjectData overrides
    on the exception types are marked [Obsolete] with the framework's own
    wording. That is what silences SYSLIB0051 and CS0672 on net10.0. Keep the
    attribute if you touch those members; do not delete the members, because
    they are part of the public surface this library promises.

  * Tests use xUnit.v3 with SilverAssertions available. Any call inside a test
    that accepts a CancellationToken must be passed
    TestContext.Current.CancellationToken, or xUnit1051 fires.

  * These tests are a port of the upstream BouncyCastle NUnit suite, so they
    keep the upstream test class and method names rather than the CodeBrix
    <ClassUnderTest>Tests / snake_case convention. Follow the surrounding file
    when adding to an existing test class.


ARCHITECTURE
--------------------------------------------------------------------------------

Folder layout matches sub-namespace, one level per namespace segment, so
CodeBrix.Cryptography.Crypto.Digests lives in
src/CodeBrix.Cryptography/Crypto/Digests/. (Upstream used lowercase folder names
that did not always match -- its `util` folder held Org.BouncyCastle.Utilities,
and `openpgp` held Org.BouncyCastle.Bcpg.OpenPgp -- so paths differ from
upstream even though file names do not.)

The library is layered, and it is worth knowing which layer you are in:

  1. Math          BigInteger and the EC / field arithmetic everything else
                   builds on. Performance-critical; several files have x86
                   intrinsics variants gated by
                   CodeBrix.Cryptography.Runtime.Intrinsics.X86.

  2. Crypto        The algorithm layer. Engines are raw block/stream ciphers,
                   Modes wrap an engine into a mode of operation, Paddings add
                   padding, Digests/Macs/Signers/Agreement/Generators are the
                   corresponding primitives, and Parameters carries keyed and
                   unkeyed inputs (KeyParameter, ParametersWithIV,
                   ParametersWithRandom, AeadParameters, ...).

  3. Asn1          Encoding of everything the higher layers exchange. The
                   sub-namespaces are one-per-specification and are almost
                   entirely mechanical structure definitions plus OID constants.

  4. Security      A name/OID-driven facade over layer 2, so callers can select
                   an algorithm at runtime from a string. If you are adding an
                   algorithm, it usually needs registering here too.

  5. Protocol      X509, Pkix, Pkcs, Cms, Cmp, Crmf, Ocsp, Tsp, Bcpg (OpenPGP),
                   OpenSsl and Tls. These compose layers 2-4; they rarely do
                   arithmetic themselves.

  6. Pqc           Post-quantum algorithms, structured like layer 2 with its own
                   Asn1 and Utilities helpers.

Cross-cutting: Utilities (Arrays, Encoders, IO, Collections, Zlib, Bzip2,
Properties) is used by every layer, and Runtime.Intrinsics.X86 is the single
place CPU features are probed.


TESTING
--------------------------------------------------------------------------------

    dotnet test CodeBrix.Cryptography.slnx

That runs clean out of the box: 0 failed, 1912 passed, 230 skipped. No external
checkout, download or environment variable is needed.

The suite is the upstream BouncyCastle NUnit suite translated to xUnit.v3 -- 546
test files, 2142 test cases. Fixtures come from three places:

  * tests/CodeBrix.Cryptography.Tests/data/ -- 303 files inherited from
    bc-csharp's own crypto/test/data (MIT, like the rest of that repository),
    embedded into the test assembly as resources under the logical prefix
    "CodeBrix.Cryptography.data.". SimpleTest.GetTestData and
    GetTestDataAsStream read these.

  * test-data/ -- 1762 files (18 MB), copied next to the test assembly at build
    time. SimpleTest.FindTestResource reads these. Three origins, all recorded in
    THIRD-PARTY-NOTICES.txt:
      - 193 files generated by this library itself (TLS/DTLS credentials, sample
        credentials, CMS SignedData, nested-ASN.1 and CMP fixtures);
      - 11 Ascon known-answer vectors from github.com/ascon/ascon-c (CC0-1.0);
      - the NIST PKITS 2011 archive, extracted verbatim (US government public
        information).
    Regenerate the self-authored ones with:

        CODEBRIX_CRYPTOGRAPHY_REGENERATE_TEST_DATA=1 dotnet test \
            --filter "FullyQualifiedName~TestDataGeneration"

    The generators live in tests/CodeBrix.Cryptography.Tests/TestDataGeneration/
    and are skipped unless that variable is set, so they never run in CI. They
    produce the ML-DSA / ML-KEM / SLH-DSA sample credentials, the CMS SignedData
    samples, the TLS and DTLS certificate and key set, and the deeply-nested
    ASN.1 stress fixtures.

  * bc-test-data -- OPTIONAL, and the reason 108 tests are skipped by default.

THE SKIPPED TESTS AND HOW TO RUN THEM
--------------------------------------------------------------------------------

BouncyCastle keeps the remaining fixtures in a separate repository,
https://github.com/bcgit/bc-test-data.git -- roughly 4.6 GB, with no licence
file anywhere in it. Without a licence those files cannot be redistributed
inside an MIT-licensed repository, and several individual files would breach
GitHub's size limits anyway (picnic ships a single 40 MB vector file), so the
108 tests that read them are skipped rather than failing.

What remains gated is the post-quantum known-answer vectors from the individual
NIST PQC submission packages (Saber, Picnic, NTRU Prime, Classic McEliece, NTRU,
FrodoKEM, HQC, BIKE, Falcon, and parts of ML-KEM / ML-DSA / SLH-DSA), the LMS/HSS
vectors, and one Grain-128AEAD vector. Each submission carries its own unstated
terms, and self-generated vectors would only prove the library agrees with
itself, so neither sourcing nor authoring them is available.

To run them:

  1. Clone https://github.com/bcgit/bc-test-data.git so that it sits BESIDE this
     repository -- the two directories must be siblings, for example
     ~/GitHome/CodeBrix.Cryptography and ~/GitHome/bc-test-data.

  2. Set CODEBRIX_CRYPTOGRAPHY_USE_BC_TEST_DATA=1.

        CODEBRIX_CRYPTOGRAPHY_USE_BC_TEST_DATA=1 dotnet test CodeBrix.Cryptography.slnx

With both in place the full suite passes: 0 failed, 2020 passed, 122 skipped
(the remaining 122 are upstream's own [Explicit] benchmarks and [Ignore]d
tests plus this repository's four fixture-generation utilities, none of which
run by default).

The gating lives in Utilities/Test/BcTestData.cs. Every affected test carries
Skip = BcTestData.SkipReason with SkipUnless = nameof(BcTestData.IsAvailable),
and each affected class carries a <remarks> block saying the same thing. A
fixture in this repository always wins over the external copy, so opting in can
only add files -- it can never change the result of a test that already passes.

Two things worth knowing when a test fails:

  * Check whether it calls FindTestResource (test-data, plus the optional
    external set) or GetTestDataAsStream (embedded, always present) before
    assuming a real regression.

  * Tls.Tests.DtlsPskProtocolTest.BadClientKeyTimeout and BadServerKeyTimeout
    assert that a DTLS handshake times out, so their outcome depends on elapsed
    time rather than on a value. Under the CPU contention of a full parallel run
    the handshake used to fail a different way first, making them flaky. They are
    now in TimingSensitiveCollection, which xUnit runs on its own and never
    alongside another collection; that removed the flakiness. If you add another
    timing-dependent test, put it in that collection rather than skipping it.
