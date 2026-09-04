================================================================================
AGENT-README: CodeBrix.Cryptography
A Guide for AI Coding Agents — CONSUMING the
CodeBrix.Cryptography.MitLicenseForever NuGet package
================================================================================


OVERVIEW
========

CodeBrix.Cryptography is a fully managed, cross-platform, general-purpose
cryptography library. It covers ASN.1 encoding, a very broad set of symmetric
and asymmetric ciphers, digests, MACs, signatures and key agreement, key
derivation and password hashing, post-quantum algorithms, TLS and DTLS,
OpenPGP, CMS/S-MIME, PKCS, CMP, CRMF, OCSP, TSP, X.509 certificate and CRL
handling and path validation, and OpenSSL PEM interoperability.

Target framework: .NET 10 or later. There is no multi-targeting; netstandard
and .NET Framework are not supported.

Provenance: CodeBrix.Cryptography is a port of BouncyCastle.NET
(https://github.com/bcgit/bc-csharp), narrowed to a single modern .NET target
and rehomed under the CodeBrix.Cryptography namespace. Every public type keeps
its upstream name, member names and signatures, so the library is a drop-in
replacement for the BouncyCastle.Cryptography NuGet package: migrating a
consumer is a package swap plus a find-and-replace of "Org.BouncyCastle" with
"CodeBrix.Cryptography". Do NOT write upstream namespaces in code that consumes
this package — there is no Org.BouncyCastle namespace in the assembly.

Because the public API is the upstream API, the upstream documentation and the
very large body of sample code on the web apply verbatim once the namespace
prefix is adjusted. This file documents the surface as it exists in this
package; where a behavioural detail is not covered here, the upstream
documentation is the reference.

The public surface is roughly 1,900 public types across about 140 namespaces.
Nothing below is a complete enumeration; every section names the types that
actually get used and gives a working shape for each.


POST-QUANTUM ALGORITHMS ARE EXPERIMENTAL
========================================

Upstream states that its NIST Post-Quantum Cryptography Standardization
implementations "should all be considered EXPERIMENTAL and subject to change or
removal", and that carries over to this port unchanged — the code is the same
code.

That covers everything under CodeBrix.Cryptography.Pqc.*, plus the ML-KEM,
ML-DSA and SLH-DSA support in CodeBrix.Cryptography.Crypto. Treat their APIs,
parameter sets and encodings as unstable across releases. In particular, do not
use them to protect data that has to remain readable after an upgrade, and do
not assume a key or signature produced by one version will be parseable by the
next.

The classical algorithms carry no such caveat.


INSTALLATION
============

NuGet package id:  CodeBrix.Cryptography.MitLicenseForever

    dotnet add package CodeBrix.Cryptography.MitLicenseForever

The ".MitLicenseForever" suffix is part of the PACKAGE ID only. The assembly,
the root namespace and every type live under "CodeBrix.Cryptography" without
the suffix.

NuGet dependencies: none. The library depends only on the .NET base class
library. There are no native libraries, no P/Invoke, and no platform-specific
assets — it runs anywhere .NET 10 runs.

License: MIT.

Requirements: .NET 10 or later. AES-NI, PCLMULQDQ, AVX2 and similar x86
intrinsics are used opportunistically when the running CPU supports them and
fall back to portable managed code otherwise; nothing needs to be configured
for this.


KEY NAMESPACES / USINGS
=======================

There is no single entry-point type; the library is a large toolbox, organised
the same way upstream organises it. Namespaces map one-to-one onto feature
areas:

  CodeBrix.Cryptography.Asn1          ASN.1 objects, DER/BER/DL encoding, and
                                      the OID and structure definitions for
                                      X.509, PKCS, CMS, CMP, CRMF, OCSP, TSP,
                                      X9.62, NIST, SEC, EdEC, TeleTrusT,
                                      CryptoPro, GM, Kisa, Ntt, Rosstandart,
                                      Icao, Isara, Misc and many other specs.
                                      Sub-namespaces mirror the specifications.

  CodeBrix.Cryptography.Crypto        The algorithm layer. Sub-namespaces:
                                      Engines (block and stream ciphers),
                                      Modes, Paddings, Digests, Macs, Signers,
                                      Generators, Agreement (+ .Kdf, .Srp,
                                      .JPake), Parameters, Prng (+ .Drbg),
                                      Kems, Encodings, EC, Fpe, IO, Operators,
                                      Utilities.

  CodeBrix.Cryptography.Math          BigInteger, elliptic-curve arithmetic
                                      (EC, EC.Custom.Sec, EC.Custom.GM,
                                      EC.Rfc7748, EC.Rfc8032, EC.Endo,
                                      EC.Multiplier, EC.Abc), Field, Raw and
                                      BinPoly.

  CodeBrix.Cryptography.Security      The name/OID-driven facade over the
                                      algorithm layer: SecureRandom,
                                      DigestUtilities, CipherUtilities,
                                      SignerUtilities, MacUtilities,
                                      GeneratorUtilities, ParameterUtilities,
                                      AgreementUtilities, WrapperUtilities,
                                      KemUtilities, PbeUtilities,
                                      PrivateKeyFactory, PublicKeyFactory,
                                      DotNetUtilities, JksStore.
                                      Security.Certificates holds
                                      CertificateEncodingException,
                                      CrlException and friends.

  CodeBrix.Cryptography.X509          X509Certificate, X509Crl, X509CrlEntry,
                                      the V1/V2/V3 generators, the certificate,
                                      CRL, attribute-certificate and cert-pair
                                      parsers, SubjectPublicKeyInfoFactory, and
                                      X509.Store selectors. X509.Extension has
                                      the key-identifier structures.

  CodeBrix.Cryptography.Pkix          PKIX certificate path building and
                                      validation (RFC 3280/5280), name
                                      constraints and trust anchors.

  CodeBrix.Cryptography.Pkcs          PKCS#8/#10/#12 — Pkcs12Store,
                                      Pkcs12StoreBuilder,
                                      Pkcs10CertificationRequest,
                                      PrivateKeyInfoFactory,
                                      Pkcs8EncryptedPrivateKeyInfo and friends.

  CodeBrix.Cryptography.Cms           CMS / S-MIME: signed, enveloped,
                                      authenticated, auth-enveloped, digested,
                                      encrypted and compressed data, plus the
                                      streaming parsers and generators.

  CodeBrix.Cryptography.Tls           TLS 1.0-1.3 and DTLS 1.0-1.2 client and
                                      server. Tls.Crypto is the pluggable
                                      crypto abstraction and
                                      Tls.Crypto.Impl.BC is the in-box
                                      implementation of it.

  CodeBrix.Cryptography.Bcpg          OpenPGP. Bcpg is the packet layer
                                      (ArmoredInputStream,
                                      ArmoredOutputStream, the algorithm tag
                                      enums) and Bcpg.OpenPgp is the high-level
                                      API (PgpPublicKeyRing, PgpSecretKeyRing,
                                      PgpEncryptedDataGenerator,
                                      PgpSignatureGenerator, PgpObjectFactory).

  CodeBrix.Cryptography.Pqc.*         Post-quantum: Pqc.Crypto.Bike,
                                      .Cmce, .Crystals.Dilithium, .Falcon,
                                      .Frodo, .Hqc, .Lms, .Ntru, .NtruPrime,
                                      .Picnic, .Saber, .SphincsPlus, plus
                                      Pqc.Asn1 and Pqc.Crypto.Utilities.
                                      (ML-KEM, ML-DSA and SLH-DSA live in
                                      Crypto.Kems / Crypto.Signers, not here.)

  CodeBrix.Cryptography.Cmp           CMP (RFC 4210) message handling.
  CodeBrix.Cryptography.Crmf          CRMF (RFC 4211) certificate requests.
  CodeBrix.Cryptography.Ocsp          OCSP request and response handling.
  CodeBrix.Cryptography.Tsp           RFC 3161 timestamping.
  CodeBrix.Cryptography.OpenSsl       PEM reading and writing (PemReader,
                                      PemWriter, Pkcs8Generator,
                                      MiscPemGenerator, IPasswordFinder).
  CodeBrix.Cryptography.Operators     CmsContentEncryptorBuilder,
                                      CmsKeyTransRecipientInfoGenerator, and
                                      Operators.Utilities algorithm finders.
                                      NOTE: Asn1SignatureFactory and
                                      Asn1VerifierFactory are NOT here — they
                                      are in Crypto.Operators.
  CodeBrix.Cryptography.Mozilla       SignedPublicKeyAndChallenge.
  CodeBrix.Cryptography.Runtime       Runtime.Intrinsics.X86 CPU feature gates.
  CodeBrix.Cryptography.Utilities     Arrays, BigIntegers, Bytes, Integers,
                                      Longs, Strings, Objects, Spans, Enums,
                                      Properties, plus Encoders (Hex, Base64,
                                      UrlBase64), IO (Streams, .Pem,
                                      .Compression), Collections, Date, Net,
                                      Zlib and Bzip2.

COMMON USING COMBINATIONS

    // Symmetric encryption
    using CodeBrix.Cryptography.Crypto;              // AesUtilities, IDigest, ...
    using CodeBrix.Cryptography.Crypto.Engines;
    using CodeBrix.Cryptography.Crypto.Modes;
    using CodeBrix.Cryptography.Crypto.Paddings;
    using CodeBrix.Cryptography.Crypto.Parameters;
    using CodeBrix.Cryptography.Security;            // SecureRandom

    // Asymmetric keys, signatures and certificates
    using CodeBrix.Cryptography.Asn1.X509;           // X509Name, KeyUsage, ...
    using CodeBrix.Cryptography.Crypto;
    using CodeBrix.Cryptography.Crypto.Generators;
    using CodeBrix.Cryptography.Crypto.Operators;    // Asn1SignatureFactory
    using CodeBrix.Cryptography.Crypto.Parameters;
    using CodeBrix.Cryptography.Math;                // BigInteger
    using CodeBrix.Cryptography.Security;
    using CodeBrix.Cryptography.X509;

    // PEM interop
    using CodeBrix.Cryptography.OpenSsl;
    using CodeBrix.Cryptography.Security;

    // OpenPGP
    using CodeBrix.Cryptography.Bcpg;
    using CodeBrix.Cryptography.Bcpg.OpenPgp;

    // TLS
    using CodeBrix.Cryptography.Tls;
    using CodeBrix.Cryptography.Tls.Crypto;
    using CodeBrix.Cryptography.Tls.Crypto.Impl.BC;

Note that CodeBrix.Cryptography.Math.BigInteger is this library's own
BigInteger, not System.Numerics.BigInteger. If a file needs both, alias one of
them.


CORE API REFERENCE
==================

The reference below is organised by feature area. Every signature shown was
taken from this package's source. Code fragments are indicative shapes; the
COMPLETE EXAMPLES section further down has end-to-end programs.


RANDOMNESS
----------

    namespace CodeBrix.Cryptography.Security

    public class SecureRandom : Random
        public SecureRandom()
        public SecureRandom(IRandomGenerator generator)
        public SecureRandom(IRandomGenerator generator, int autoSeedLengthInBytes)
        public static SecureRandom GetInstance(string algorithm)
        public static SecureRandom GetInstance(string algorithm, bool autoSeed)
        public static byte[] GetNextBytes(SecureRandom secureRandom, int length)
        public static void Fill(Span<byte> buffer, SecureRandom secureRandom)
        public virtual byte[] GenerateSeed(int length)
        public virtual void SetSeed(byte[] seed)
        public override void NextBytes(byte[] buf)
        public override void NextBytes(Span<byte> buffer)
        public virtual int NextInt()
        public virtual long NextLong()

    var random = new SecureRandom();
    random.NextBytes(buffer);

SecureRandom is the source every generator in the library expects. Prefer it
over System.Random and reuse one instance. CryptoServicesRegistrar.GetSecureRandom()
(namespace CodeBrix.Cryptography.Crypto) returns a shared instance, and
GetSecureRandom(SecureRandom) returns the argument when it is non-null and the
shared instance otherwise — useful when a SecureRandom parameter is optional.

Deterministic / NIST DRBG variants live in
CodeBrix.Cryptography.Crypto.Prng: SP800SecureRandomBuilder,
X931SecureRandomBuilder, DigestRandomGenerator, VMPCRandomGenerator,
CryptoApiRandomGenerator, and the Prng.Drbg engines behind them.


SYMMETRIC ENCRYPTION — AEAD (the usual choice for "encrypt this")
-----------------------------------------------------------------

AEAD ciphers implement IAeadCipher (namespace
CodeBrix.Cryptography.Crypto.Modes) and all share the same shape:

    public sealed class GcmBlockCipher : IAeadBlockCipher
        public GcmBlockCipher(IBlockCipher c)
        public void Init(bool forEncryption, ICipherParameters parameters)
        public int GetOutputSize(int len)
        public int GetUpdateOutputSize(int len)
        public void ProcessAadBytes(byte[] inBytes, int inOff, int len)
        public void ProcessAadBytes(ReadOnlySpan<byte> input)
        public int ProcessBytes(byte[] input, int inOff, int len, byte[] output,
                    int outOff)
        public int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        public int DoFinal(byte[] output, int outOff)
        public int DoFinal(Span<byte> output)
        public byte[] GetMac()
        public void Reset()

    // AES engine selection, namespace CodeBrix.Cryptography.Crypto
    public static class AesUtilities
        public static IBlockCipher CreateEngine()      // AES-NI when available
        public static bool IsHardwareAccelerated { get; }

    // namespace CodeBrix.Cryptography.Crypto.Parameters
    public class AeadParameters : ICipherParameters
        public AeadParameters(KeyParameter key, int macSize, byte[] nonce)
        public AeadParameters(KeyParameter key, int macSize, byte[] nonce,
                    byte[] associatedText)
        public virtual KeyParameter Key { get; }
        public virtual int MacSize { get; }            // in BITS
        public virtual byte[] GetNonce()
        public virtual byte[] GetAssociatedText()

    public class KeyParameter : ICipherParameters
        public KeyParameter(byte[] key)
        public KeyParameter(byte[] key, int keyOff, int keyLen)
        public KeyParameter(ReadOnlySpan<byte> key)
        public byte[] GetKey()
        public int KeyLength { get; }

    var cipher = new GcmBlockCipher(AesUtilities.CreateEngine());
    cipher.Init(forEncryption: true,
        new AeadParameters(new KeyParameter(key), 128, nonce, associatedData));
    byte[] output = new byte[cipher.GetOutputSize(input.Length)];
    int n = cipher.ProcessBytes(input, 0, input.Length, output, 0);
    n += cipher.DoFinal(output, n);

Allocate the output buffer with GetOutputSize(inputLength). On decryption,
DoFinal throws InvalidCipherTextException when the tag does not verify — that
exception IS the authentication failure, so never swallow it.

The AEAD family, all in CodeBrix.Cryptography.Crypto.Modes and all following
the same Init/ProcessAadBytes/ProcessBytes/DoFinal shape:

    GcmBlockCipher          AES-GCM and any 128-bit-block engine
    GcmSivBlockCipher       AES-GCM-SIV (nonce-misuse resistant)
    CcmBlockCipher          AES-CCM
    EaxBlockCipher          EAX
    OcbBlockCipher          OCB
    KCcmBlockCipher         Kalyna/DSTU CCM
    ChaCha20Poly1305        ChaCha20-Poly1305 (RFC 7539); takes a
                            ParametersWithIV(KeyParameter, nonce) or an
                            AeadParameters; ctor is
                            ChaCha20Poly1305() / ChaCha20Poly1305(IMac poly1305)
    XChaCha20Poly1305       XChaCha20-Poly1305 (24-byte nonce)
    AsconAead128            Ascon-AEAD128 (NIST lightweight winner)


SYMMETRIC ENCRYPTION — CLASSIC BLOCK-CIPHER MODES AND PADDING
--------------------------------------------------------------

Composition is explicit: an engine goes inside a mode, and the mode goes inside
a buffered cipher that applies padding.

    // namespace CodeBrix.Cryptography.Crypto.Modes
    public sealed class CbcBlockCipher : IBlockCipherMode
        public CbcBlockCipher(IBlockCipher cipher)
        public void Init(bool forEncryption, ICipherParameters parameters)
        public int GetBlockSize()
        public int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        public void Reset()

    // namespace CodeBrix.Cryptography.Crypto.Paddings
    public class PaddedBufferedBlockCipher : BufferedBlockCipher
        public PaddedBufferedBlockCipher(IBlockCipher cipher,
                    IBlockCipherPadding padding)
        public PaddedBufferedBlockCipher(IBlockCipherMode cipherMode,
                    IBlockCipherPadding padding)
        public PaddedBufferedBlockCipher(IBlockCipherMode cipherMode)   // PKCS#7
        public override void Init(bool forEncryption, ICipherParameters parameters)
        public override int GetOutputSize(int length)
        public override int ProcessBytes(byte[] input, int inOff, int length,
                    byte[] output, int outOff)
        public override int DoFinal(byte[] output, int outOff)

    var cipher = new PaddedBufferedBlockCipher(
        new CbcBlockCipher(AesUtilities.CreateEngine()), new Pkcs7Padding());
    cipher.Init(forEncryption: true,
        new ParametersWithIV(new KeyParameter(key), iv));
    byte[] output = new byte[cipher.GetOutputSize(input.Length)];
    int n = cipher.ProcessBytes(input, 0, input.Length, output, 0);
    n += cipher.DoFinal(output, n);

Modes: CbcBlockCipher, CfbBlockCipher, OfbBlockCipher, SicBlockCipher (CTR),
EcbBlockCipher, CtsBlockCipher, GOFBBlockCipher, KCtrBlockCipher,
OpenPgpCfbBlockCipher.

Paddings (all IBlockCipherPadding, namespace Crypto.Paddings): Pkcs7Padding,
ISO7816d4Padding, ISO10126d2Padding, X923Padding, TbcPadding,
ZeroBytePadding.

Engines (namespace Crypto.Engines) include AesEngine, AesEngine_X86,
AesLightEngine, AriaEngine, BlowfishEngine, CamelliaEngine, Cast5Engine,
Cast6Engine, DesEngine, DesEdeEngine, Dstu7624Engine, GOST28147Engine,
IdeaEngine, NoekeonEngine, RC2Engine, RC532Engine, RC564Engine, RC6Engine,
RijndaelEngine, SEEDEngine, SerpentEngine, TnepresEngine, SkipjackEngine,
SM4Engine, TEAEngine, XTEAEngine, ThreefishEngine, TwofishEngine; stream
ciphers ChaChaEngine, ChaCha7539Engine, XChaCha20Engine, Salsa20Engine,
XSalsa20Engine, HC128Engine, HC256Engine, ISAACEngine, RC4Engine, VMPCEngine,
VMPCKSA3Engine, Grain128AEADEngine, SparkleEngine, AsconEngine; key wrapping
AesWrapEngine, AesWrapPadEngine, AriaWrapEngine, AriaWrapPadEngine,
CamelliaWrapEngine, DesEdeWrapEngine, RC2WrapEngine, SEEDWrapEngine,
RFC3211WrapEngine, RFC3394WrapEngine, Rfc5649WrapEngine, Dstu7624WrapEngine;
and asymmetric RsaEngine, RSABlindedEngine, ElGamalEngine, NaccacheSternEngine,
SM2Engine, IesEngine.

Format-preserving encryption lives in CodeBrix.Cryptography.Crypto.Fpe:
FpeFf1Engine, FpeFf3_1Engine, FpeEngine, SP80038G.

For streaming, CodeBrix.Cryptography.Crypto.IO has CipherStream, DigestStream,
MacStream, SignerStream and the matching sinks.


HASHING, XOFs AND MACs
----------------------

    // namespace CodeBrix.Cryptography.Crypto
    public interface IDigest
        string AlgorithmName { get; }
        int GetDigestSize();
        int GetByteLength();
        void Update(byte input);
        void BlockUpdate(byte[] input, int inOff, int inLen);
        void BlockUpdate(ReadOnlySpan<byte> input);
        int DoFinal(byte[] output, int outOff);
        int DoFinal(Span<byte> output);
        void Reset();

    public interface IMac                 // same shape, plus:
        void Init(ICipherParameters parameters);
        int GetMacSize();

    IDigest digest = new Sha256Digest();               // Crypto.Digests
    digest.BlockUpdate(data, 0, data.Length);
    byte[] hash = new byte[digest.GetDigestSize()];
    digest.DoFinal(hash, 0);

    IMac mac = new HMac(new Sha256Digest());           // Crypto.Macs
    mac.Init(new KeyParameter(key));
    mac.BlockUpdate(data, 0, data.Length);
    byte[] tag = new byte[mac.GetMacSize()];
    mac.DoFinal(tag, 0);

    // namespace CodeBrix.Cryptography.Crypto.Macs
    public class HMac : IMac
        public HMac(IDigest digest)
        public HMac(IDigest digest, int blockLength)
        public virtual IDigest GetUnderlyingDigest()

Name- and OID-driven resolution, when the algorithm is chosen at runtime:

    // namespace CodeBrix.Cryptography.Security
    public static class DigestUtilities
        public static IDigest GetDigest(string algorithm)              // "SHA-256"
        public static IDigest GetDigest(DerObjectIdentifier id)
        public static IDigest GetDigest(AlgorithmIdentifier algID)
        public static byte[] CalculateDigest(string algorithm, byte[] input)
        public static byte[] CalculateDigest(string algorithm, byte[] buf, int off,
                    int len)
        public static byte[] CalculateDigest(string algorithm,
                    ReadOnlySpan<byte> buffer)
        public static byte[] CalculateDigest(DerObjectIdentifier id, byte[] input)
        public static byte[] DoFinal(IDigest digest)
        public static byte[] DoFinal(IDigest digest, byte[] input)
        public static string GetAlgorithmName(DerObjectIdentifier oid)
        public static DerObjectIdentifier GetObjectIdentifier(string mechanism)

    public static class MacUtilities
        public static IMac GetMac(string algorithm)                    // "HMACSHA256"
        public static IMac GetMac(DerObjectIdentifier id)
        public static byte[] CalculateMac(string algorithm, ICipherParameters cp,
                    byte[] input)
        public static byte[] DoFinal(IMac mac)
        public static byte[] DoFinal(IMac mac, byte[] input)

Digests (namespace Crypto.Digests): Sha1Digest, Sha224Digest, Sha256Digest,
Sha384Digest, Sha512Digest, Sha512tDigest, SHA3Digest, ShakeDigest,
CSHAKEDigest, KeccakDigest, Blake2bDigest, Blake2sDigest, Blake2xsDigest,
Blake3Digest, MD2Digest, MD4Digest, MD5Digest, RipeMD128/160/256/320Digest,
SM3Digest, SkeinDigest, WhirlpoolDigest, GOST3411Digest,
GOST3411_2012_256Digest, GOST3411_2012_512Digest, DSTU7564Digest,
Haraka256Digest, Haraka512Digest, AsconHash256, AsconXof128, AsconCXof128,
ISAPDigest, PhotonBeetleDigest, ParallelHash, TupleHash, NullDigest,
NonMemoableDigest, ShortenedDigest, Prehash.

MACs (namespace Crypto.Macs): HMac, CMac, GMac, Poly1305, SipHash, KMac,
SkeinMac, CbcBlockCipherMac, CfbBlockCipherMac, ISO9797Alg3Mac, GOST28147Mac,
DSTU7564Mac, DSTU7624Mac, VMPCMac.


KEY DERIVATION AND PASSWORD HASHING
-----------------------------------

    // namespace CodeBrix.Cryptography.Crypto.Generators

    public class SCrypt
        public static byte[] Generate(byte[] P, byte[] S, int N, int r, int p,
                    int dkLen)

    public sealed class BCrypt
        public static byte[] Generate(byte[] password, byte[] salt, int cost)
        public static byte[] Generate(byte[] password, byte[] salt, int cost,
                    bool addTerminator)
        public static byte[] PasswordToByteArray(char[] password)
        // OpenBsdBCrypt (same namespace) produces/checks the "$2y$..." string form

    public sealed class Argon2BytesGenerator
        public Argon2BytesGenerator()
        public Argon2BytesGenerator(TaskFactory taskFactory)   // parallel lanes
        public void Init(Argon2Parameters parameters)
        public int GenerateBytes(byte[] password, byte[] output)
        public int GenerateBytes(byte[] password, byte[] output, int outOff,
                    int outLen)
        public int GenerateBytes(char[] password, byte[] output)

    // namespace CodeBrix.Cryptography.Crypto.Parameters
    public sealed class Argon2Parameters
        public static readonly int Argon2d, Argon2i, Argon2id
        public static readonly int Version10, Version13
        public sealed class Builder
            public Builder(int type)
            public Builder WithSalt(byte[] salt)
            public Builder WithSecret(byte[] secret)
            public Builder WithAdditional(byte[] additional)
            public Builder WithIterations(int iterations)
            public Builder WithParallelism(int parallelism)
            public Builder WithMemoryAsKB(int memory)
            public Builder WithMemoryPowOfTwo(int memory)
            public Builder WithVersion(int version)
            public Builder WithCharToByteConverter(ICharToByteConverter converter)
            public Argon2Parameters Build()

    var argon2Params = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
        .WithVersion(Argon2Parameters.Version13)
        .WithSalt(salt).WithIterations(3).WithParallelism(4)
        .WithMemoryAsKB(65536).Build();
    var argon2 = new Argon2BytesGenerator();
    argon2.Init(argon2Params);
    byte[] derived = new byte[32];
    argon2.GenerateBytes(passwordBytes, derived);

PBKDF2 and the other PBE generators derive from PbeParametersGenerator
(namespace CodeBrix.Cryptography.Crypto):

    public abstract class PbeParametersGenerator
        public virtual void Init(byte[] password, byte[] salt, int iterationCount)
        public virtual void Init(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt,
                    int iterationCount)
        public abstract ICipherParameters GenerateDerivedParameters(string algorithm,
                    int keySize)
        public abstract ICipherParameters GenerateDerivedParameters(string algorithm,
                    int keySize, int ivSize)
        public abstract ICipherParameters GenerateDerivedMacParameters(int keySize)
        public static byte[] Pkcs5PasswordToBytes(char[] password)
        public static byte[] Pkcs5PasswordToUtf8Bytes(char[] password)
        public static byte[] Pkcs12PasswordToBytes(char[] password)

    public class Pkcs5S2ParametersGenerator : PbeParametersGenerator    // PBKDF2
        public Pkcs5S2ParametersGenerator()                 // SHA-1 default
        public Pkcs5S2ParametersGenerator(IDigest digest)

    var pbkdf2 = new Pkcs5S2ParametersGenerator(new Sha256Digest());
    pbkdf2.Init(PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(password),
                salt, 600_000);
    var keyParam = (KeyParameter)pbkdf2.GenerateDerivedMacParameters(256);

keySize and ivSize on those three methods are in BITS, not bytes.

Sibling generators: Pkcs5S1ParametersGenerator (PBKDF1),
Pkcs12ParametersGenerator (the PKCS#12 KDF),
OpenSSLPBEParametersGenerator (EVP_BytesToKey).

HKDF (RFC 5869):

    public sealed class HkdfBytesGenerator : IDerivationFunction
        public HkdfBytesGenerator(IDigest hash)
        public void Init(IDerivationParameters parameters)
        public int GenerateBytes(byte[] output, int outOff, int length)
        public int GenerateBytes(Span<byte> output)
        public IDigest Digest { get; }

    // namespace CodeBrix.Cryptography.Crypto.Parameters
    public class HkdfParameters : IDerivationParameters
        public HkdfParameters(byte[] ikm, byte[] salt, byte[] info)
        public static HkdfParameters SkipExtractParameters(byte[] ikm, byte[] info)
        public static HkdfParameters DefaultParameters(byte[] ikm)

    var hkdf = new HkdfBytesGenerator(new Sha256Digest());
    hkdf.Init(new HkdfParameters(ikm, salt, info));
    byte[] okm = new byte[32];
    hkdf.GenerateBytes(okm, 0, okm.Length);

Other KDFs in Crypto.Generators: Kdf1BytesGenerator, Kdf2BytesGenerator
(X9.63/ISO 18033), Mgf1BytesGenerator, KDFCounterBytesGenerator,
KDFFeedbackBytesGenerator, KDFDoublePipelineIterationBytesGenerator
(SP 800-108), plus the concatenation KDFs under Crypto.Agreement.Kdf.


RSA
---

    // namespace CodeBrix.Cryptography.Crypto.Generators
    public class RsaKeyPairGenerator : IAsymmetricCipherKeyPairGenerator
        public virtual void Init(KeyGenerationParameters parameters)
        public virtual AsymmetricCipherKeyPair GenerateKeyPair()

    // namespace CodeBrix.Cryptography.Crypto
    public class KeyGenerationParameters
        public KeyGenerationParameters(SecureRandom random, int strength)
        public SecureRandom Random { get; }
        public int Strength { get; }

    public class AsymmetricCipherKeyPair
        public AsymmetricCipherKeyPair(AsymmetricKeyParameter publicParameter,
                    AsymmetricKeyParameter privateParameter)
        public AsymmetricKeyParameter Public { get; }
        public AsymmetricKeyParameter Private { get; }

    // namespace CodeBrix.Cryptography.Crypto.Parameters — for explicit control
    public class RsaKeyGenerationParameters : KeyGenerationParameters
        public RsaKeyGenerationParameters(BigInteger publicExponent,
                    SecureRandom random, int strength, int certainty)

    var generator = new RsaKeyPairGenerator();
    generator.Init(new KeyGenerationParameters(random, 3072));
    AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();

Raw RSA is never used bare — wrap the engine in a padding scheme:

    // namespace CodeBrix.Cryptography.Crypto.Engines
    public class RsaEngine : IAsymmetricBlockCipher
        public virtual void Init(bool forEncryption, ICipherParameters parameters)
        public virtual int GetInputBlockSize()
        public virtual int GetOutputBlockSize()
        public virtual byte[] ProcessBlock(byte[] inBuf, int inOff, int inLen)
    // RSABlindedEngine is the side-channel-hardened variant; prefer it for
    // private-key operations.

    // namespace CodeBrix.Cryptography.Crypto.Encodings
    public class Pkcs1Encoding : IAsymmetricBlockCipher
        public Pkcs1Encoding(IAsymmetricBlockCipher cipher)
        public Pkcs1Encoding(IAsymmetricBlockCipher cipher, int pLen)
        public Pkcs1Encoding(IAsymmetricBlockCipher cipher, byte[] fallback)
        public const string StrictLengthEnabledProperty =
                    "Org.BouncyCastle.Pkcs1.Strict"

    public class OaepEncoding : IAsymmetricBlockCipher
        public OaepEncoding(IAsymmetricBlockCipher cipher)
        public OaepEncoding(IAsymmetricBlockCipher cipher, IDigest hash)
        public OaepEncoding(IAsymmetricBlockCipher cipher, IDigest hash,
                    byte[] encodingParams)
        public OaepEncoding(IAsymmetricBlockCipher cipher, IDigest hash,
                    IDigest mgf1Hash, byte[] encodingParams)

    var rsa = new OaepEncoding(new RSABlindedEngine(), new Sha256Digest());
    rsa.Init(forEncryption: true, pair.Public);
    byte[] wrapped = rsa.ProcessBlock(sessionKey, 0, sessionKey.Length);

RSA can only encrypt up to GetInputBlockSize() bytes; use it to wrap a
symmetric key, not to encrypt a message.

Signatures go through the ISigner facade (see the next section) with names such
as "SHA256withRSA" or "SHA256withRSAandMGF1" (RSASSA-PSS). The direct classes
are RsaDigestSigner, PssSigner, Iso9796d2Signer and X931Signer in
CodeBrix.Cryptography.Crypto.Signers.


SIGNATURES — THE ISigner FACADE
-------------------------------

    // namespace CodeBrix.Cryptography.Crypto
    public interface ISigner
        string AlgorithmName { get; }
        void Init(bool forSigning, ICipherParameters parameters);
        void Update(byte input);
        void BlockUpdate(byte[] input, int inOff, int inLen);
        void BlockUpdate(ReadOnlySpan<byte> input);
        int GetMaxSignatureSize();
        byte[] GenerateSignature();
        bool VerifySignature(byte[] signature);
        void Reset();

    // namespace CodeBrix.Cryptography.Security
    public static class SignerUtilities
        public static ISigner GetSigner(string algorithm)
        public static ISigner GetSigner(DerObjectIdentifier id)
        public static ISigner InitSigner(string algorithm, bool forSigning,
                    AsymmetricKeyParameter privateKey, SecureRandom random)
        public static ISigner InitSigner(DerObjectIdentifier algorithmOid,
                    bool forSigning, AsymmetricKeyParameter privateKey,
                    SecureRandom random)
        public static DerObjectIdentifier GetObjectIdentifier(string mechanism)
        public static string GetEncodingName(DerObjectIdentifier oid)
        public static ICollection<string> Algorithms { get; }

    ISigner signer = SignerUtilities.InitSigner("SHA256withRSA", forSigning: true,
                                                pair.Private, random);
    signer.BlockUpdate(data, 0, data.Length);
    byte[] signature = signer.GenerateSignature();

    ISigner verifier = SignerUtilities.InitSigner("SHA256withRSA", forSigning: false,
                                                  pair.Public, null);
    verifier.BlockUpdate(data, 0, data.Length);
    bool ok = verifier.VerifySignature(signature);

Concrete signers in CodeBrix.Cryptography.Crypto.Signers: DsaSigner,
DsaDigestSigner, ECDsaSigner, ECNRSigner, ECGOST3410Signer, Dstu4145Signer,
GOST3410Signer, GOST3410DigestSigner, Ed25519Signer, Ed25519ctxSigner,
Ed25519phSigner, Ed448Signer, Ed448phSigner, RsaDigestSigner, PssSigner,
Iso9796d2Signer, Iso9796d2PssSigner, X931Signer, SM2Signer, GenericSigner,
MLDsaSigner, HashMLDsaSigner, SlhDsaSigner, HashSlhDsaSigner. The k-value
strategies are HMacDsaKCalculator (RFC 6979 deterministic) and
RandomDsaKCalculator.


ELLIPTIC CURVE, EdDSA AND X25519
--------------------------------

Curve lookup — four registries, all with the same static shape
(GetByName / GetByOid / GetName / GetOid / Names / *Lazy):

    CodeBrix.Cryptography.Asn1.X9.ECNamedCurveTable      // the union of them all
    CodeBrix.Cryptography.Asn1.Sec.SecNamedCurves        // secp*/sect*
    CodeBrix.Cryptography.Asn1.Nist.NistNamedCurves      // P-256, P-384, ...
    CodeBrix.Cryptography.Asn1.TeleTrust.TeleTrusTNamedCurves
    CodeBrix.Cryptography.Crypto.EC.CustomNamedCurves    // optimised field impls

        public static X9ECParameters GetByName(string name)
        public static X9ECParameters GetByOid(DerObjectIdentifier oid)
        public static DerObjectIdentifier GetOid(string name)
        public static string GetName(DerObjectIdentifier oid)
        public static IEnumerable<string> Names { get; }

    // namespace CodeBrix.Cryptography.Asn1.X9
    public class X9ECParameters
        public ECCurve Curve { get; }
        public ECPoint G { get; }
        public BigInteger N { get; }
        public BigInteger H { get; }
        public byte[] GetSeed()

Domain parameters and key generation:

    // namespace CodeBrix.Cryptography.Crypto.Parameters
    public class ECDomainParameters
        public ECDomainParameters(X9ECParameters x9)
        public ECDomainParameters(ECCurve curve, ECPoint g, BigInteger n)
        public ECDomainParameters(ECCurve curve, ECPoint g, BigInteger n,
                    BigInteger h)
        public ECDomainParameters(ECCurve curve, ECPoint g, BigInteger n,
                    BigInteger h, byte[] seed)
        public static ECDomainParameters LookupName(string name)
        public static ECDomainParameters FromX9ECParameters(
                    X9ECParameters x9ECParameters)
        public ECCurve Curve { get; }
        public ECPoint G { get; }
        public BigInteger N { get; }
        public BigInteger H { get; }
        public X9ECParameters ToX9ECParameters()

    public class ECKeyGenerationParameters : KeyGenerationParameters
        public ECKeyGenerationParameters(ECDomainParameters domainParameters,
                    SecureRandom random)
        public ECKeyGenerationParameters(DerObjectIdentifier publicKeyParamSet,
                    SecureRandom random)
        public ECDomainParameters DomainParameters { get; }
        public DerObjectIdentifier PublicKeyParamSet { get; }

    public class ECPrivateKeyParameters : ECKeyParameters
        public ECPrivateKeyParameters(BigInteger d, ECDomainParameters parameters)
        public ECPrivateKeyParameters(string algorithm, BigInteger d,
                    ECDomainParameters parameters)
        public ECPrivateKeyParameters(string algorithm, BigInteger d,
                    DerObjectIdentifier publicKeyParamSet)
        public BigInteger D { get; }

    public class ECPublicKeyParameters : ECKeyParameters
        public ECPublicKeyParameters(ECPoint q, ECDomainParameters parameters)
        public ECPublicKeyParameters(string algorithm, ECPoint q,
                    ECDomainParameters parameters)
        public ECPublicKeyParameters(string algorithm, ECPoint q,
                    DerObjectIdentifier publicKeyParamSet)
        public ECPoint Q { get; }

    // namespace CodeBrix.Cryptography.Crypto.Generators
    public class ECKeyPairGenerator : IAsymmetricCipherKeyPairGenerator
        public ECKeyPairGenerator()
        public ECKeyPairGenerator(string algorithm)     // "ECDSA", "ECDH", ...
        public void Init(KeyGenerationParameters parameters)
        public AsymmetricCipherKeyPair GenerateKeyPair()

    var ecGen = new ECKeyPairGenerator("ECDSA");
    ecGen.Init(new ECKeyGenerationParameters(
        ECNamedCurveTable.GetOid("secp256r1"), random));
    AsymmetricCipherKeyPair ecPair = ecGen.GenerateKeyPair();

ECDSA directly (r/s pair rather than a DER signature):

    // namespace CodeBrix.Cryptography.Crypto.Signers
    public class ECDsaSigner : IDsa
        public ECDsaSigner()
        public ECDsaSigner(IDsaKCalculator kCalculator)
        public virtual void Init(bool forSigning, ICipherParameters parameters)
        public virtual BigInteger[] GenerateSignature(byte[] message)   // { r, s }
        public virtual bool VerifySignature(byte[] message, BigInteger r,
                    BigInteger s)
        public virtual BigInteger Order { get; }

Use SignerUtilities.GetSigner("SHA256withECDSA") instead when a DER-encoded
signature is wanted.

Ed25519 / Ed448:

    // namespace CodeBrix.Cryptography.Crypto.Generators
    public class Ed25519KeyPairGenerator : IAsymmetricCipherKeyPairGenerator
    public class Ed448KeyPairGenerator  : IAsymmetricCipherKeyPairGenerator

    // namespace CodeBrix.Cryptography.Crypto.Parameters
    public sealed class Ed25519PrivateKeyParameters : AsymmetricKeyParameter
        public static readonly int KeySize, SignatureSize
        public Ed25519PrivateKeyParameters(SecureRandom random)
        public Ed25519PrivateKeyParameters(byte[] buf)
        public Ed25519PrivateKeyParameters(byte[] buf, int off)
        public Ed25519PrivateKeyParameters(ReadOnlySpan<byte> buf)
        public Ed25519PrivateKeyParameters(Stream input)
        public byte[] GetEncoded()
        public Ed25519PublicKeyParameters GeneratePublicKey()

    public sealed class Ed25519PublicKeyParameters : AsymmetricKeyParameter
        public static readonly int KeySize
        public Ed25519PublicKeyParameters(byte[] buf)
        public Ed25519PublicKeyParameters(ReadOnlySpan<byte> buf)
        public byte[] GetEncoded()

    // namespace CodeBrix.Cryptography.Crypto.Signers
    public class Ed25519Signer : ISigner
        public Ed25519Signer()
        public virtual void Init(bool forSigning, ICipherParameters parameters)
        public virtual void BlockUpdate(byte[] buf, int off, int len)
        public virtual byte[] GenerateSignature()
        public virtual bool VerifySignature(byte[] signature)

    var edPrivate = new Ed25519PrivateKeyParameters(random);
    var edPublic = edPrivate.GeneratePublicKey();
    var edSigner = new Ed25519Signer();
    edSigner.Init(forSigning: true, edPrivate);
    edSigner.BlockUpdate(data, 0, data.Length);
    byte[] edSignature = edSigner.GenerateSignature();

Key agreement:

    // namespace CodeBrix.Cryptography.Crypto.Agreement
    public class ECDHBasicAgreement : IBasicAgreement
        // Init takes YOUR OWN private key:
        public virtual void Init(ICipherParameters parameters)
        public virtual int GetFieldSize()
        public virtual BigInteger CalculateAgreement(ICipherParameters pubKey)

    public sealed class X25519Agreement : IRawAgreement
        // Init takes YOUR OWN private key:
        public void Init(ICipherParameters parameters)
        public int AgreementSize { get; }
        public void CalculateAgreement(ICipherParameters publicKey, byte[] buf,
                    int off)
        public void CalculateAgreement(ICipherParameters publicKey, Span<byte> buf)

    // namespace CodeBrix.Cryptography.Crypto.Parameters
    public sealed class X25519PrivateKeyParameters : AsymmetricKeyParameter
        public static readonly int KeySize, SecretSize
        public X25519PrivateKeyParameters(SecureRandom random)
        public X25519PrivateKeyParameters(byte[] buf)
        public X25519PublicKeyParameters GeneratePublicKey()
        public byte[] GetEncoded()
        public void GenerateSecret(X25519PublicKeyParameters publicKey, byte[] buf,
                    int off)

    var agreement = new ECDHBasicAgreement();
    agreement.Init(myPair.Private);
    BigInteger z = agreement.CalculateAgreement(theirPublicKey);
    byte[] shared = BigIntegers.AsUnsignedByteArray(agreement.GetFieldSize(), z);

Never use the raw agreement output as a key — run it through a KDF (HKDF above,
or the *WithKdf agreement variants). Other agreements: ECDHCBasicAgreement,
ECDHRawAgreement, ECDhcRawAgreement, ECMqvBasicAgreement, ECVkoAgreement,
DHAgreement, DHBasicAgreement, X448Agreement, SM2KeyExchange, and the SRP-6a
and J-PAKE participants under Crypto.Agreement.Srp / .JPake.

Runtime resolution: AgreementUtilities.GetBasicAgreement("ECDH"),
GetRawAgreement("X25519"), GetBasicAgreementWithKdf(agreeAlg, wrapAlg);
GeneratorUtilities.GetKeyPairGenerator("ECDSA") /
GetKeyGenerator("AES"); CipherUtilities.GetCipher("AES/CBC/PKCS7Padding");
WrapperUtilities.GetWrapper("AESWRAP"); KemUtilities.GetEncapsulator(name) /
GetDecapsulator(name) / TryGet* — all in CodeBrix.Cryptography.Security.


KEY ENCODING AND PEM INTEROPERABILITY
-------------------------------------

Converting between key objects and the standard encodings:

    // namespace CodeBrix.Cryptography.Security
    public static class PrivateKeyFactory
        // PKCS#8 PrivateKeyInfo encoding:
        public static AsymmetricKeyParameter CreateKey(byte[] privateKeyInfoData)
        public static AsymmetricKeyParameter CreateKey(Stream inStr)
        public static AsymmetricKeyParameter CreateKey(PrivateKeyInfo keyInfo)
        public static AsymmetricKeyParameter DecryptKey(char[] passPhrase,
                    byte[] encryptedPrivateKeyInfoData)
        public static AsymmetricKeyParameter DecryptKey(char[] passPhrase,
                    EncryptedPrivateKeyInfo encInfo)
        public static byte[] EncryptKey(...)

    public static class PublicKeyFactory
        // SubjectPublicKeyInfo encoding:
        public static AsymmetricKeyParameter CreateKey(byte[] keyInfoData)
        public static AsymmetricKeyParameter CreateKey(Stream inStr)
        public static AsymmetricKeyParameter CreateKey(SubjectPublicKeyInfo keyInfo)

    // namespace CodeBrix.Cryptography.Pkcs
    public static class PrivateKeyInfoFactory
        public static PrivateKeyInfo CreatePrivateKeyInfo(
                    AsymmetricKeyParameter privateKey)
        public static PrivateKeyInfo CreatePrivateKeyInfo(
                    AsymmetricKeyParameter privateKey, Asn1Set attributes)

    // namespace CodeBrix.Cryptography.X509
    public static class SubjectPublicKeyInfoFactory
        public static SubjectPublicKeyInfo CreateSubjectPublicKeyInfo(
                    AsymmetricKeyParameter publicKey)

    byte[] pkcs8 = PrivateKeyInfoFactory
        .CreatePrivateKeyInfo(pair.Private).GetEncoded();
    byte[] spki = SubjectPublicKeyInfoFactory
        .CreateSubjectPublicKeyInfo(pair.Public).GetEncoded();
    var restoredPrivate = PrivateKeyFactory.CreateKey(pkcs8);
    var restoredPublic = PublicKeyFactory.CreateKey(spki);

PEM ("-----BEGIN ...-----") reading and writing:

    // namespace CodeBrix.Cryptography.OpenSsl
    public class PemReader : Utilities.IO.Pem.PemReader
        public PemReader(TextReader reader)
        public PemReader(TextReader reader, IPasswordFinder pFinder)
        public object ReadObject()

    public class PemWriter : Utilities.IO.Pem.PemWriter    // IDisposable
        public PemWriter(TextWriter writer)
        public void WriteObject(object obj)
        public void WriteObject(object obj, string algorithm, char[] password,
                    SecureRandom random)
        // inherited: void WriteObject(PemObjectGenerator objGen), TextWriter Writer,
        //            int GetOutputSize(PemObject obj), void Dispose()
        // Dispose() disposes the underlying TextWriter.

    public interface IPasswordFinder
        char[] GetPassword();

    public class Pkcs8Generator : PemObjectGenerator
        public Pkcs8Generator(AsymmetricKeyParameter privKey)
        public Pkcs8Generator(AsymmetricKeyParameter privKey, string algorithm)
        public Pkcs8Generator(AsymmetricKeyParameter privKey,
                    DerObjectIdentifier algorithm)
        public SecureRandom SecureRandom { get; set; }
        public char[] Password { get; set; }
        public int IterationCount { get; set; }
        public PemObject Generate()
        // algorithm constants: PbeSha1_3DES, PbeSha1_2DES, PbeSha1_RC4_128,
        //                      PbeSha1_RC4_40, PbeSha1_RC2_128, PbeSha1_RC2_40

    public class MiscPemGenerator : PemObjectGenerator
        public MiscPemGenerator(object obj)
        public MiscPemGenerator(object obj, string algorithm, char[] password,
                    SecureRandom random)

PemReader.ReadObject() is typed `object`, and WHAT it returns depends on the
PEM label. This is the single most common source of InvalidCastException when
consuming this area, so the mapping is worth memorising:

    -----BEGIN RSA PRIVATE KEY-----          AsymmetricCipherKeyPair
    -----BEGIN DSA PRIVATE KEY-----          AsymmetricCipherKeyPair
    -----BEGIN EC PRIVATE KEY-----           AsymmetricCipherKeyPair
    -----BEGIN PRIVATE KEY-----              AsymmetricKeyParameter  (PKCS#8)
    -----BEGIN ENCRYPTED PRIVATE KEY-----    AsymmetricKeyParameter
    -----BEGIN PUBLIC KEY-----               AsymmetricKeyParameter
    -----BEGIN RSA PUBLIC KEY-----           AsymmetricKeyParameter (RsaKeyParameters)
    -----BEGIN CERTIFICATE-----              X509Certificate
    -----BEGIN X509 CERTIFICATE-----         X509Certificate
    -----BEGIN X509 CRL-----                 X509Crl
    -----BEGIN CERTIFICATE REQUEST-----      Pkcs10CertificationRequest
    -----BEGIN NEW CERTIFICATE REQUEST-----  Pkcs10CertificationRequest
    -----BEGIN ATTRIBUTE CERTIFICATE-----    X509V2AttributeCertificate
    -----BEGIN EC PARAMETERS-----            Asn1.X9.X962Parameters
    -----BEGIN PKCS7----- / -----BEGIN CMS-----  Asn1.Cms.ContentInfo

Any other label throws IOException ("unrecognised object"). ReadObject()
returns null at end of stream. A legacy "Proc-Type: 4,ENCRYPTED" private key
requires an IPasswordFinder, otherwise PasswordException is thrown.

The lower-level PEM plumbing is in CodeBrix.Cryptography.Utilities.IO.Pem:
PemObject(string type, byte[] content), PemHeader, PemObjectGenerator,
PemObjectParser, PemReader.ReadPemObject(), PemWriter.WriteObject(PemObjectGenerator).

OpenSSH key blobs: Crypto.Utilities.OpenSshPublicKeyUtilities.ParsePublicKey /
EncodePublicKey and OpenSshPrivateKeyUtilities.ParsePrivateKeyBlob /
EncodePrivateKey.

Interop with System.Security.Cryptography types goes through
CodeBrix.Cryptography.Security.DotNetUtilities: FromX509Certificate,
ToX509Certificate, GetRsaKeyPair(RSA), GetRsaPublicKey(RSA), ToRSA,
GetDsaKeyPair(DSA), GetECDsaKeyPair(ECDsa), GetKeyPair(AsymmetricAlgorithm),
GetSubjectPublicKeyInfo(X509Certificate2).


X.509 CERTIFICATES AND CRLs
---------------------------

    // namespace CodeBrix.Cryptography.X509
    public class X509V3CertificateGenerator
        public X509V3CertificateGenerator()
        public X509V3CertificateGenerator(X509Certificate template)
        public void SetSerialNumber(BigInteger serialNumber)
        public void SetIssuerDN(X509Name issuer)
        public void SetSubjectDN(X509Name subject)
        public void SetNotBefore(DateTime date)
        public void SetNotAfter(DateTime date)
        public void SetPublicKey(AsymmetricKeyParameter publicKey)
        public void SetSubjectPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo)
        public void AddExtension(DerObjectIdentifier oid, bool critical,
                    Asn1Encodable extensionValue)
        public void AddExtension(string oid, bool critical, byte[] extensionValue)
        public void AddExtensions(X509Extensions extensions)
        public void CopyAndAddExtension(DerObjectIdentifier oid, bool critical,
                    X509Certificate cert)
        public void Reset()
        public X509Certificate Generate(ISignatureFactory signatureFactory)
        public IEnumerable<string> SignatureAlgNames { get; }
    // X509V1CertificateGenerator and X509V2AttributeCertificateGenerator are
    // the same shape for their respective profiles.

    // namespace CodeBrix.Cryptography.Crypto.Operators   <- NOT .Operators
    public class Asn1SignatureFactory : ISignatureFactory
        public Asn1SignatureFactory(string algorithm,
                    AsymmetricKeyParameter privateKey)
        public Asn1SignatureFactory(string algorithm,
                    AsymmetricKeyParameter privateKey, SecureRandom random)
        public Asn1SignatureFactory(AlgorithmIdentifier algorithm,
                    AsymmetricKeyParameter privateKey)
        public object AlgorithmDetails { get; }
        public static IEnumerable<string> SignatureAlgNames { get; }

    public class Asn1VerifierFactory : IVerifierFactory
        public Asn1VerifierFactory(string algorithm, AsymmetricKeyParameter publicKey)
        public Asn1VerifierFactory(AlgorithmIdentifier algorithm,
                    AsymmetricKeyParameter publicKey)

    public class Asn1VerifierFactoryProvider : IVerifierFactoryProvider
        public Asn1VerifierFactoryProvider(AsymmetricKeyParameter publicKey)

    public class X509Certificate
        public X509Certificate(byte[] certData)
        public virtual int Version { get; }
        public virtual BigInteger SerialNumber { get; }
        public virtual X509Name IssuerDN { get; }
        public virtual X509Name SubjectDN { get; }
        public virtual DateTime NotBefore { get; }
        public virtual DateTime NotAfter { get; }
        public virtual bool IsValidNow { get; }
        public virtual bool IsValid(DateTime time)
        public virtual void CheckValidity()
        public virtual void CheckValidity(DateTime time)
        public virtual void Verify(AsymmetricKeyParameter key)
        public virtual bool IsSignatureValid(AsymmetricKeyParameter key)
        public virtual AsymmetricKeyParameter GetPublicKey()
        public virtual SubjectPublicKeyInfo SubjectPublicKeyInfo { get; }
        public virtual bool[] GetKeyUsage()
        public virtual IList<DerObjectIdentifier> GetExtendedKeyUsage()
        public virtual int GetBasicConstraints()
        public virtual IList<IList<object>> GetSubjectAlternativeNames()
        public virtual GeneralNames GetSubjectAlternativeNameExtension()
        public virtual string SigAlgName { get; }
        public virtual string SigAlgOid { get; }
        public virtual byte[] GetEncoded()

    public class X509CertificateParser
        public X509Certificate ReadCertificate(byte[] input)
        public X509Certificate ReadCertificate(Stream inStream)
        public IList<X509Certificate> ReadCertificates(byte[] input)
        public IList<X509Certificate> ReadCertificates(Stream inStream)
        public IEnumerable<X509Certificate> ParseCertificates(Stream inStream)
    // X509CrlParser, X509AttrCertParser and X509CertPairParser mirror it.

X509CertificateParser reads DER or PEM, single objects or PKCS#7/certificate
bundles. CheckValidity() throws (CertificateNotYetValidException /
CertificateExpiredException); IsValidNow returns a bool. Verify() throws on a
bad signature; IsSignatureValid() returns a bool.

Distinguished names and extension values come from
CodeBrix.Cryptography.Asn1.X509:

    public class X509Name
        // dirName e.g. "CN=example.test, O=Acme, C=US"
        public X509Name(string dirName)
        public X509Name(bool reverse, string dirName)
        public X509Name(IList<DerObjectIdentifier> oids, IList<string> values)
        public static readonly DerObjectIdentifier C, O, OU, CN, L, ST, E, ...

    public class BasicConstraints : Asn1Encodable
        public BasicConstraints(bool cA)
        public BasicConstraints(int pathLenConstraint)   // implies cA = true
        public bool IsCA()

    public class KeyUsage : DerBitString
        public KeyUsage(int usage)
        public const int DigitalSignature, NonRepudiation, KeyEncipherment,
                         DataEncipherment, KeyAgreement, KeyCertSign, CrlSign,
                         EncipherOnly, DecipherOnly

    public class X509Extensions
        public static readonly DerObjectIdentifier BasicConstraints, KeyUsage,
            ExtendedKeyUsage, SubjectKeyIdentifier, AuthorityKeyIdentifier,
            SubjectAlternativeName, ...

    certGen.AddExtension(X509Extensions.BasicConstraints, critical: true,
        new BasicConstraints(cA: false));
    certGen.AddExtension(X509Extensions.KeyUsage, critical: true,
        new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));

CRLs:

    public class X509V2CrlGenerator
        public void SetIssuerDN(X509Name issuer)
        public void SetThisUpdate(DateTime date)
        public void SetNextUpdate(DateTime date)
        public void AddCrlEntry(BigInteger userCertificate, DateTime revocationDate,
                    int reason)
        public void AddCrl(X509Crl other)
        public void AddExtension(DerObjectIdentifier oid, bool critical,
                    Asn1Encodable extensionValue)
        public X509Crl Generate(ISignatureFactory signatureFactory)

    public class X509Crl
        public X509Crl(byte[] encoding)
        public virtual X509Name IssuerDN { get; }
        public virtual DateTime ThisUpdate { get; }
        public virtual DateTime? NextUpdate { get; }
        public virtual X509CrlEntry GetRevokedCertificate(BigInteger serialNumber)
        public virtual ISet<X509CrlEntry> GetRevokedCertificates()
        public virtual void Verify(AsymmetricKeyParameter publicKey)
        public virtual bool IsSignatureValid(AsymmetricKeyParameter key)


PKCS#10 REQUESTS AND PKCS#12 KEY STORES
---------------------------------------

    // namespace CodeBrix.Cryptography.Pkcs
    public class Pkcs10CertificationRequest
        public Pkcs10CertificationRequest(byte[] encoded)
        public Pkcs10CertificationRequest(Stream input)
        public AsymmetricKeyParameter GetPublicKey()
        public bool Verify()
        public bool Verify(AsymmetricKeyParameter publicKey)
        public bool Verify(IVerifierFactory verifier)
        public X509Extensions GetRequestedExtensions()

    public class Pkcs12StoreBuilder
        public Pkcs12StoreBuilder()
        public Pkcs12StoreBuilder SetCertAlgorithm(DerObjectIdentifier certAlgorithm)
        public Pkcs12StoreBuilder SetKeyAlgorithm(DerObjectIdentifier keyAlgorithm)
        public Pkcs12StoreBuilder SetEnableOracleTrustedKeyUsage(bool enable)
        public Pkcs12StoreBuilder SetOverwriteFriendlyName(bool overwriteFriendlyName)
        public Pkcs12StoreBuilder SetReverseCertificates(bool reverseCertificates)
        public Pkcs12StoreBuilder SetUseDerEncoding(bool useDerEncoding)
        public Pkcs12Store Build()

    public class Pkcs12Store
        public void Load(Stream input, char[] password)
        public void Save(Stream stream, char[] password, SecureRandom random)
        public void SetKeyEntry(string alias, AsymmetricKeyEntry keyEntry,
                    X509CertificateEntry[] chain)
        public void SetCertificateEntry(string alias, X509CertificateEntry certEntry)
        public void SetFriendlyName(string alias, string newFriendlyName)
        public void DeleteEntry(string alias)
        public AsymmetricKeyEntry GetKey(string alias)
        public X509CertificateEntry GetCertificate(string alias)
        public X509CertificateEntry[] GetCertificateChain(string alias)
        public string GetCertificateAlias(X509Certificate cert)
        public bool IsKeyEntry(string alias)
        public bool IsCertificateEntry(string alias)
        public bool ContainsAlias(string alias)
        public IEnumerable<string> Aliases { get; }
        public int Count { get; }
        public const string IgnoreUselessPasswordProperty =
                    "Org.BouncyCastle.Pkcs12.IgnoreUselessPassword"

    public class AsymmetricKeyEntry : Pkcs12Entry
        public AsymmetricKeyEntry(AsymmetricKeyParameter key)
        public AsymmetricKeyParameter Key { get; }

    public class X509CertificateEntry : Pkcs12Entry
        public X509CertificateEntry(X509Certificate cert)
        public X509Certificate Certificate { get; }

    var store = new Pkcs12StoreBuilder().Build();
    store.SetKeyEntry("my-key", new AsymmetricKeyEntry(pair.Private),
        new[] { new X509CertificateEntry(certificate) });
    using (var fs = File.Create("store.p12"))
        store.Save(fs, "password".ToCharArray(), random);

PKCS#8 encryption is also available directly:
Pkcs8EncryptedPrivateKeyInfoBuilder / Pkcs8EncryptedPrivateKeyInfo and
EncryptedPrivateKeyInfoFactory, all in CodeBrix.Cryptography.Pkcs. A Java
keystore can be read with CodeBrix.Cryptography.Security.JksStore.


PKIX CERTIFICATE PATH BUILDING AND VALIDATION
---------------------------------------------

    // namespace CodeBrix.Cryptography.Pkix
    public class TrustAnchor
        public TrustAnchor(X509Certificate trustedCert, byte[] nameConstraints)
        public TrustAnchor(X509Name caPrincipal, AsymmetricKeyParameter pubKey,
                    byte[] nameConstraints)
        public X509Certificate TrustedCert { get; }
        public AsymmetricKeyParameter CAPublicKey { get; }

    public class PkixParameters
        public PkixParameters(ISet<TrustAnchor> trustAnchors)
        public const int PkixValidityModel = 0, ChainValidityModel = 1
        public virtual bool IsRevocationEnabled { get; set; }
        public virtual bool IsExplicitPolicyRequired { get; set; }
        public virtual bool IsAnyPolicyInhibited { get; set; }
        public virtual bool IsPolicyMappingInhibited { get; set; }
        public virtual DateTime? Date { get; set; }
        public virtual int ValidityModel { get; set; }
        public virtual void AddStoreCert(IStore<X509Certificate> storeCert)
        public virtual void AddStoreCrl(IStore<X509Crl> storeCrl)
        public virtual void AddCertPathChecker(PkixCertPathChecker checker)
        public virtual void SetInitialPolicies(ISet<string> initialPolicies)
        public virtual void SetTargetConstraintsCert(
                    ISelector<X509Certificate> targetConstraintsCert)

    public class PkixBuilderParameters : PkixParameters
        public PkixBuilderParameters(ISet<TrustAnchor> trustAnchors,
                    ISelector<X509Certificate> targetConstraintsCert)
        public static PkixBuilderParameters GetInstance(PkixParameters pkixParams)
        public virtual int MaxPathLength { get; set; }

    public class PkixCertPathBuilder
        public virtual PkixCertPathBuilderResult Build(PkixBuilderParameters pkixParams)

    public class PkixCertPathBuilderResult : PkixCertPathValidatorResult
        public PkixCertPath CertPath { get; }

    public class PkixCertPathValidator
        public virtual PkixCertPathValidatorResult Validate(
                    PkixCertPath certPath, PkixParameters paramsPkix)

    public class PkixCertPathValidatorResult
        public TrustAnchor TrustAnchor { get; }
        public PkixPolicyNode PolicyTree { get; }
        public AsymmetricKeyParameter SubjectPublicKey { get; }

    public class PkixCertPath
        public PkixCertPath(IList<X509Certificate> certificates)
        public PkixCertPath(Stream inStream)
        public virtual IList<X509Certificate> Certificates { get; }
        public virtual byte[] GetEncoded()
        public virtual byte[] GetEncoded(string encoding)   // "PkiPath", "PKCS7"

    var anchors = new HashSet<TrustAnchor> { new TrustAnchor(rootCert, null) };
    var target = new X509CertStoreSelector { Subject = endCert.SubjectDN };
    var buildParams = new PkixBuilderParameters(anchors, target);
    buildParams.AddStoreCert(CollectionUtilities.CreateStore(intermediates));
    buildParams.AddStoreCrl(CollectionUtilities.CreateStore(crls));
    buildParams.Date = DateTime.UtcNow;
    buildParams.IsRevocationEnabled = true;
    PkixCertPath path = new PkixCertPathBuilder().Build(buildParams).CertPath;

Failures throw PkixCertPathBuilderException / PkixCertPathValidatorException.
Store plumbing lives in CodeBrix.Cryptography.Utilities.Collections:
IStore<T>, ISelector<T>, CollectionUtilities.CreateStore<T>(IEnumerable<T>).
Selectors: X509CertStoreSelector, X509CrlStoreSelector,
X509AttrCertStoreSelector, X509CertPairStoreSelector (all in X509.Store).
Attribute-certificate paths use PkixAttrCertPathBuilder /
PkixAttrCertPathValidator; name-constraint checking is
PkixNameConstraintValidator.


CMS / S-MIME
------------

    // namespace CodeBrix.Cryptography.Cms
    public class CmsSignedDataGenerator : CmsSignedGenerator
        public CmsSignedDataGenerator()
        public CmsSignedDataGenerator(SecureRandom random)
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert,
                    string digestOID)
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert,
                    string encryptionOID, string digestOID)
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID,
                    string digestOID)
        public void AddSignerInfoGenerator(SignerInfoGenerator signerInfoGenerator)
        public CmsSignedData Generate(CmsProcessable content)
        public CmsSignedData Generate(CmsProcessable content, bool encapsulate)
        public CmsSignedData Generate(string signedContentType,
                    CmsProcessable content, bool encapsulate)
        public SignerInformationStore GenerateCounterSigners(SignerInformation signer)

    public abstract class CmsSignedGenerator
        public void AddCertificate(X509Certificate cert)
        public void AddCertificates(IStore<X509Certificate> certStore)
        public void AddCrl(X509Crl crl)
        public void AddCrls(IStore<X509Crl> crlStore)
        public void AddSigners(SignerInformationStore signerStore)
        public static readonly string DigestSha1, DigestSha224, DigestSha256,
            DigestSha384, DigestSha512, DigestSha3_256, DigestShake256,
            DigestMD5, DigestSM3, DigestRipeMD160, ...
        public static readonly string EncryptionRsa, EncryptionDsa,
            EncryptionECDsa, EncryptionRsaPss, ...

    public class CmsSignedData
        public CmsSignedData(byte[] sigBlock)
        public CmsSignedData(CmsProcessable signedContent,
                    byte[] sigBlock)   // detached
        public CmsSignedData(Stream sigData)
        public SignerInformationStore GetSignerInfos()
        public IStore<X509Certificate> GetCertificates()
        public IStore<X509Crl> GetCrls()
        public CmsProcessable SignedContent { get; }
        public DerObjectIdentifier SignedContentType { get; }
        public bool IsDetachedSignature { get; }
        public bool IsCertificateManagementMessage { get; }
        public int Version { get; }
        public byte[] GetEncoded()
        public static CmsSignedData ReplaceSigners(CmsSignedData signedData, ...)

    public class SignerInformation
        public bool Verify(AsymmetricKeyParameter pubKey)
        public bool Verify(X509Certificate cert)
        public SignerID SignerID { get; }
        public string DigestAlgOid { get; }
        public string EncryptionAlgOid { get; }
        public Asn1.Cms.AttributeTable SignedAttributes { get; }
        public Asn1.Cms.AttributeTable UnsignedAttributes { get; }
        public byte[] GetSignature()
        public byte[] GetContentDigest()
        public SignerInformationStore GetCounterSignatures()

    public class SignerInformationStore : IEnumerable<SignerInformation>
        public IList<SignerInformation> GetSigners()
        public SignerInformation GetFirstSigner(SignerID selector)
        public int Count { get; }

    public class CmsProcessableByteArray : CmsTypedData
        public CmsProcessableByteArray(byte[] bytes)
        public CmsProcessableByteArray(DerObjectIdentifier type, byte[] bytes)
        public byte[] GetByteArray()
    // CmsProcessableFile and CmsProcessableInputStream are the streaming peers.

    var signedGen = new CmsSignedDataGenerator();
    signedGen.AddSigner(pair.Private, certificate, CmsSignedGenerator.DigestSha256);
    signedGen.AddCertificates(CollectionUtilities.CreateStore(new[] { certificate }));
    CmsSignedData signed = signedGen.Generate(
        new CmsProcessableByteArray(data), encapsulate: true);

Enveloped (encrypted-for-recipients) data:

    public class CmsEnvelopedDataGenerator : CmsEnvelopedGenerator
        public CmsEnvelopedDataGenerator()
        public CmsEnvelopedDataGenerator(SecureRandom random)
        public CmsEnvelopedData Generate(CmsProcessable content, string encryptionOid)
        public CmsEnvelopedData Generate(CmsProcessable content, string encryptionOid,
                    int keySize)
        public CmsEnvelopedData Generate(CmsTypedData content,
                    DerObjectIdentifier encryptionOid)

    public abstract class CmsEnvelopedGenerator
        public void AddKeyTransRecipient(X509Certificate cert)
        public void AddKeyTransRecipient(AsymmetricKeyParameter pubKey,
                    byte[] subKeyId)
        public void AddKekRecipient(...)
        public void AddPasswordRecipient(...)
        public void AddKeyAgreementRecipient(...)
        public void AddRecipientInfoGenerator(
                    RecipientInfoGenerator recipientInfoGenerator)
        public static readonly string Aes128Cbc, Aes192Cbc, Aes256Cbc,
            Aes128Gcm, Aes256Gcm, Aes128Ccm, Aes256Ccm, DesEde3Cbc,
            Camellia256Cbc, SeedCbc, Aes256Wrap, ...

    public class CmsEnvelopedData
        public CmsEnvelopedData(byte[] envelopedData)
        public CmsEnvelopedData(Stream envelopedData)
        public RecipientInformationStore GetRecipientInfos()
        public string EncryptionAlgOid { get; }
        public byte[] GetEncoded()

    public abstract class RecipientInformation
        public byte[] GetContent(ICipherParameters key)
        public abstract CmsTypedStream GetContentStream(ICipherParameters key)
        public RecipientID RecipientID { get; }
        public string KeyEncryptionAlgOid { get; }

    var envGen = new CmsEnvelopedDataGenerator();
    envGen.AddKeyTransRecipient(recipientCert);
    CmsEnvelopedData enveloped = envGen.Generate(
        new CmsProcessableByteArray(data), CmsEnvelopedGenerator.Aes256Cbc);

    foreach (RecipientInformation recipient in
             new CmsEnvelopedData(bytes).GetRecipientInfos().GetRecipients())
    {
        byte[] plain = recipient.GetContent(recipientPrivateKey);
    }

The rest of the CMS surface follows the same generator/parser pairing:
CmsAuthenticatedDataGenerator / CmsAuthenticatedData,
CmsCompressedDataGenerator / CmsCompressedData,
CmsDigestedData, plus the streaming variants
CmsSignedDataStreamGenerator / CmsSignedDataParser,
CmsEnvelopedDataStreamGenerator / CmsEnvelopedDataParser,
CmsCompressedDataStreamGenerator / CmsCompressedDataParser — use those for
large payloads. Attribute tables are built with
DefaultSignedAttributeTableGenerator and
DefaultAuthenticatedAttributeTableGenerator. S/MIME capability OIDs live in
CodeBrix.Cryptography.Asn1.Smime.


OPENPGP
-------

Reading key rings and messages:

    // namespace CodeBrix.Cryptography.Bcpg.OpenPgp
    public class PgpObjectFactory
        public PgpObjectFactory(Stream inputStream)
        public PgpObjectFactory(byte[] bytes)
        public PgpObject NextPgpObject()
        public IList<PgpObject> AllPgpObjects()
        public IList<T> FilterPgpObjects<T>()
        public PgpObjectFactory SetThrowForUnknownCriticalPackets(bool throwException)

    public static class PgpUtilities
        public static Stream GetDecoderStream(Stream inputStream)   // handles armor
        public static KeyParameter MakeRandomKey(SymmetricKeyAlgorithmTag algorithm,
                    SecureRandom random)
        public static KeyParameter MakeKeyFromPassPhrase(
                    SymmetricKeyAlgorithmTag algorithm, S2k s2k, char[] passPhrase)
        public static string GetDigestName(HashAlgorithmTag hashAlgorithm)
        public static string GetSignatureName(PublicKeyAlgorithmTag keyAlgorithm,
                    HashAlgorithmTag hashAlgorithm)
        public static void WriteFileToLiteralData(Stream output, char fileType,
                    FileInfo file)

    public class PgpPublicKeyRing : PgpKeyRing
        public PgpPublicKeyRing(byte[] encoding)
        public PgpPublicKeyRing(Stream inputStream)
        public virtual PgpPublicKey GetPublicKey()
        public virtual PgpPublicKey GetPublicKey(long keyId)
        public virtual PgpPublicKey GetPublicKey(byte[] fingerprint)
        public virtual IEnumerable<PgpPublicKey> GetPublicKeys()
        public virtual byte[] GetEncoded()
        public static PgpPublicKeyRing InsertPublicKey(...)
        public static PgpPublicKeyRing Join(PgpPublicKeyRing first,
                    PgpPublicKeyRing second)

    public class PgpSecretKeyRing : PgpKeyRing
        public PgpSecretKeyRing(byte[] encoding)
        public PgpSecretKeyRing(Stream inputStream)
        public PgpSecretKey GetSecretKey()
        public PgpSecretKey GetSecretKey(long keyId)
        public IEnumerable<PgpSecretKey> GetSecretKeys()
        public PgpPublicKey GetPublicKey()
        public IEnumerable<PgpPublicKey> GetPublicKeys()
        public byte[] GetEncoded()
        public static PgpSecretKeyRing CopyWithNewPassword(...)

    public class PgpPublicKeyRingBundle
        public int Count { get; }
        public IEnumerable<PgpPublicKeyRing> GetKeyRings()
        public IEnumerable<PgpPublicKeyRing> GetKeyRings(string userId,
                    bool matchPartial)
        public PgpPublicKey GetPublicKey(long keyId)
        public PgpPublicKeyRing GetPublicKeyRing(long keyId)
        public bool Contains(long keyID)
    // PgpSecretKeyRingBundle is the private-side peer.

    public class PgpSecretKey
        public PgpPrivateKey ExtractPrivateKey(char[] passPhrase)
        public PgpPrivateKey ExtractPrivateKeyUtf8(char[] passPhrase)
        public PgpPublicKey PublicKey { get; }
        public long KeyId { get; }
        public byte[] GetFingerprint()
        public bool IsSigningKey { get; }
        public bool IsMasterKey { get; }
        public IEnumerable<string> UserIds { get; }

Encryption:

    public class PgpEncryptedDataGenerator
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm)
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm,
                    bool withIntegrityPacket)
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm,
                    SecureRandom random)
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm,
                    bool withIntegrityPacket, SecureRandom random)
        public void AddMethod(PgpPublicKey key)
        public void AddMethod(char[] passPhrase, HashAlgorithmTag s2kDigest)
        public void AddMethodUtf8(char[] passPhrase, HashAlgorithmTag s2kDigest)
        public void AddMethod(char[] passPhrase, HashAlgorithmTag s2kDigest,
                    int itCount)
        public Stream Open(Stream outStr, long length)
        public Stream Open(Stream outStr, byte[] buffer)      // indefinite length
        public void Close()

    public class PgpLiteralDataGenerator
        public PgpLiteralDataGenerator()
        public PgpLiteralDataGenerator(bool oldFormat)
        public const char Binary = 'b', Text = 't', Utf8 = 'u'
        public const string Console = "_CONSOLE"
        public Stream Open(Stream outStr, char format, string name, long length,
                    DateTime modificationTime)
        public Stream Open(Stream outStr, char format, string name,
                    DateTime modificationTime, byte[] buffer)
        public Stream Open(Stream outStr, char format, FileInfo file)
        public void Close()

    public class PgpCompressedDataGenerator
        public PgpCompressedDataGenerator(CompressionAlgorithmTag algorithm)
        public PgpCompressedDataGenerator(CompressionAlgorithmTag algorithm,
                    int compression)
        public Stream Open(Stream outStr)
        public Stream Open(Stream outStr, byte[] buffer)
        public void Close()

    public class PgpEncryptedDataList : PgpObject
        public PgpEncryptedData this[int index] { get; }
        public int Count { get; }
        public bool IsEmpty { get; }
        public IEnumerable<PgpEncryptedData> GetEncryptedDataObjects()

    public class PgpPublicKeyEncryptedData : PgpEncryptedData
        public long KeyId { get; }
        public Stream GetDataStream(PgpPrivateKey privKey)
        public SymmetricKeyAlgorithmTag GetSymmetricAlgorithm(PgpPrivateKey privKey)
    // PgpPbeEncryptedData is the passphrase-based peer.

    public class PgpLiteralData : PgpObject
        public int Format { get; }
        public string FileName { get; }
        public DateTime ModificationTime { get; }
        public Stream GetInputStream()
        public Stream GetDataStream()

Signing:

    public class PgpSignatureGenerator
        public PgpSignatureGenerator(PublicKeyAlgorithmTag keyAlgorithm,
                    HashAlgorithmTag hashAlgorithm)
        public void InitSign(int sigType, PgpPrivateKey privKey)
        public void InitSign(int sigType, PgpPrivateKey privKey, SecureRandom random)
        public void Update(byte b) / Update(byte[] b, int off,
                    int len) / Update(ReadOnlySpan<byte>)
        public void SetHashedSubpackets(PgpSignatureSubpacketVector hashedPackets)
        public PgpOnePassSignature GenerateOnePassVersion(bool isNested)
        public PgpSignature Generate()
        public PgpSignature GenerateCertification(string id, PgpPublicKey pubKey)
        public PgpSignature GenerateCertification(PgpPublicKey masterKey,
                    PgpPublicKey pubKey)

    public class PgpSignature : PgpObject
        public const int BinaryDocument = 0x00, CanonicalTextDocument = 0x01,
                         DefaultCertification = 0x10, PositiveCertification = 0x13,
                         SubkeyBinding = 0x18, KeyRevocation = 0x20, ...
        public void InitVerify(PgpPublicKey pubKey)
        public void Update(byte b)
        public bool Verify()
        public bool VerifyCertification(string id, PgpPublicKey key)
        public bool IsCertification()

    public class PgpKeyPair
        public PgpKeyPair(PublicKeyAlgorithmTag algorithm,
                    AsymmetricCipherKeyPair keyPair, DateTime time)
        public PgpKeyPair(PublicKeyAlgorithmTag algorithm,
                    AsymmetricKeyParameter pubKey,
                    AsymmetricKeyParameter privKey, DateTime time)
        public PgpKeyPair(PgpPublicKey pub, PgpPrivateKey priv)
        public PgpPublicKey PublicKey { get; }
        public PgpPrivateKey PrivateKey { get; }
        public long KeyId { get; }
    // PgpKeyRingGenerator builds a full master + subkey ring.

ASCII armor (namespace CodeBrix.Cryptography.Bcpg):

    public class ArmoredOutputStream : BaseOutputStream
        public ArmoredOutputStream(Stream outStream)
        public ArmoredOutputStream(Stream outStream,
                    IDictionary<string, string> headers)
        public static readonly string HeaderVersion, HeaderComment, HeaderHash,
                                      HeaderCharset, HeaderMessageID
        public void SetHeader(string name, string val)
        public void AddHeader(string name, string val)
        public void BeginClearText(HashAlgorithmTag hashAlgorithm)
        public void EndClearText()
        public static Builder Build()

    public class ArmoredInputStream : BaseInputStream
        public ArmoredInputStream(Stream input)
        public ArmoredInputStream(Stream input, bool hasHeaders)
        public bool IsClearText()
        public bool IsEndOfStream()
        public string GetArmorHeaderLine()
        public string[] GetArmorHeaders()
        public static Builder Build()

Algorithm tag enums (namespace CodeBrix.Cryptography.Bcpg):
SymmetricKeyAlgorithmTag (Aes128 = 7, Aes192 = 8, Aes256 = 9, Cast5, TripleDes,
Camellia*, Twofish, ...), HashAlgorithmTag (Sha256 = 8, Sha384, Sha512, Sha224,
Sha3_256, Sha3_512, Sha1, ...), PublicKeyAlgorithmTag (RsaGeneral = 1, Dsa = 17,
ECDH = 18, ECDsa = 19, EdDsa_Legacy = 22, X25519 = 25, X448 = 26, Ed25519 = 27,
...), CompressionAlgorithmTag, AeadAlgorithmTag, PgpKeyFlags.


TLS AND DTLS
------------

The protocol handlers wrap a byte stream (TLS) or a datagram transport (DTLS)
and hand back a Stream / DtlsTransport once the handshake completes. The crypto
is pluggable; BcTlsCrypto is the in-box implementation and needs no
configuration.

    // namespace CodeBrix.Cryptography.Tls
    public class TlsClientProtocol : TlsProtocol
        public TlsClientProtocol()
        public TlsClientProtocol(Stream stream)
        public TlsClientProtocol(Stream input, Stream output)
        public virtual void Connect(TlsClient tlsClient)

    public class TlsServerProtocol : TlsProtocol
        public TlsServerProtocol()
        public TlsServerProtocol(Stream stream)
        public TlsServerProtocol(Stream input, Stream output)
        public void Accept(TlsServer tlsServer)

    public abstract class TlsProtocol
        public virtual Stream Stream { get; }     // application data, post-handshake
        public virtual bool IsConnected { get; }
        public virtual bool IsHandshaking { get; }
        public virtual bool IsClosed { get; }
        public virtual bool IsFailed { get; }
        public virtual void Close()
        public virtual void CloseInput()

    public abstract class AbstractTlsClient : AbstractTlsPeer, TlsClient
        // the one member you MUST implement:
        public abstract TlsAuthentication GetAuthentication();
        public override ProtocolVersion[] GetProtocolVersions()
        public override int[] GetCipherSuites()
        public virtual IDictionary<int, byte[]> GetClientExtensions()
        public virtual TlsSession GetSessionToResume()
        public virtual IList<TlsPskExternal> GetExternalPsks()
        public virtual void NotifyServerVersion(ProtocolVersion serverVersion)
        public virtual void NotifySelectedCipherSuite(int selectedCipherSuite)
        public virtual void ProcessServerExtensions(
                    IDictionary<int, byte[]> serverExtensions)
        protected override int[] GetSupportedCipherSuites()

    public abstract class DefaultTlsClient : AbstractTlsClient
        public DefaultTlsClient(TlsCrypto crypto)
    // DefaultTlsServer / AbstractTlsServer are the server-side peers;
    // PskTlsClient / PskTlsServer and SrpTlsClient / SrpTlsServer cover
    // pre-shared-key and SRP handshakes.

    public interface TlsAuthentication
        void NotifyServerCertificate(TlsServerCertificate serverCertificate);
        TlsCredentials GetClientCredentials(CertificateRequest certificateRequest);

    public interface TlsServerCertificate
        Certificate Certificate { get; }
        CertificateStatus CertificateStatus { get; }

    // namespace CodeBrix.Cryptography.Tls.Crypto.Impl.BC
    public class BcTlsCrypto : AbstractTlsCrypto
        public BcTlsCrypto()
        public BcTlsCrypto(SecureRandom entropySource)
        public override SecureRandom SecureRandom { get; }

Minimum client, verified against this package's own TLS test client:

    internal sealed class MyTlsClient : DefaultTlsClient
    {
        internal MyTlsClient() : base(new BcTlsCrypto()) { }

        public override TlsAuthentication GetAuthentication() => new Authentication();

        private sealed class Authentication : TlsAuthentication
        {
            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                // YOU must validate here. Nothing else does it for you.
                TlsCertificate[] chain =
                    serverCertificate.Certificate.GetCertificateList();
                // e.g. convert each entry with
                // X509CertificateStructure.GetInstance(chain[i].GetEncoded())
                // and run a PkixCertPathBuilder / PkixCertPathValidator over it.
            }

            public TlsCredentials GetClientCredentials(
                CertificateRequest certificateRequest) => null;   // no client cert
        }
    }

    var tcp = new TcpClient(host, port);
    var protocol = new TlsClientProtocol(tcp.GetStream());
    protocol.Connect(new MyTlsClient());
    Stream tls = protocol.Stream;        // read/write application data here
    // ... then protocol.Close();

NotifyServerCertificate is where certificate validation happens, and the
default implementation does nothing. A client that leaves it empty will happily
talk to any server presenting any certificate.

Protocol version and cipher-suite selection: override GetProtocolVersions() to
return e.g. ProtocolVersion.TLSv13.Only() or
ProtocolVersion.TLSv12.DownTo(ProtocolVersion.TLSv12), and
GetSupportedCipherSuites() to return CipherSuite constants. Alert handling is
NotifyAlertRaised / NotifyAlertReceived on AbstractTlsPeer; AlertLevel and
AlertDescription carry the codes and a GetText helper.

DTLS uses a different pair of entry points:

    public class DtlsClientProtocol
        public DtlsClientProtocol()
        public virtual DtlsTransport Connect(TlsClient client,
                    DatagramTransport transport)

    public class DtlsServerProtocol
        public virtual DtlsTransport Accept(TlsServer server,
                    DatagramTransport transport, ...)

    public class DtlsTransport : DatagramTransport
        public virtual int GetReceiveLimit()
        public virtual int GetSendLimit()
        public virtual int Receive(byte[] buf, int off, int len, int waitMillis)
        public virtual int Receive(Span<byte> buffer, int waitMillis)
        public virtual void Send(byte[] buf, int off, int len)
        public virtual void Send(ReadOnlySpan<byte> buffer)
        public virtual void Close()

Supporting types worth knowing: ProtocolVersion, CipherSuite, NamedGroup,
SignatureAlgorithm, SignatureScheme, HashAlgorithm, ExtensionType,
TlsExtensionsUtilities, TlsUtilities, ProtocolName (ALPN), TlsSession,
SessionParameters, SecurityParameters, TlsFatalAlert, TlsTimeoutException,
TlsNoCloseNotifyException, and the crypto abstractions TlsCrypto, TlsCertificate,
TlsSecret, TlsAgreement, TlsCipher, TlsHash, TlsHmac, TlsSigner, TlsVerifier,
TlsCryptoParameters, DHStandardGroups, Srp6StandardGroups.


OCSP AND TIMESTAMPING (TSP)
---------------------------

    // namespace CodeBrix.Cryptography.Ocsp
    public class OcspReqGenerator
        public void AddRequest(CertificateID certId)
        public void AddRequest(CertificateID certId,
                    X509Extensions singleRequestExtensions)
        public void SetRequestorName(X509Name requestorName)
        public void SetRequestExtensions(X509Extensions requestExtensions)
        public OcspReq Generate()
        public OcspReq Generate(ISignatureFactory signatureFactory,
                    X509Certificate[] chain)

    public class CertificateID
        public const string HashSha1 = "1.3.14.3.2.26"
        public static readonly AlgorithmIdentifier DigestSha1
        public CertificateID(string hashAlgorithm, X509Certificate issuerCert,
                    BigInteger serialNumber)
        public CertificateID(AlgorithmIdentifier digestAlgorithm,
                    X509Certificate issuerCert, BigInteger serialNumber)
        public BigInteger SerialNumber { get; }
        public bool MatchesIssuer(X509Certificate issuerCert)

    public class OcspResp
        public OcspResp(byte[] resp)
        public OcspResp(Stream inStr)
        public int Status { get; }                  // see OcspRespStatus
        public object GetResponseObject()           // BasicOcspResp when successful
        public byte[] GetEncoded()

    public class BasicOcspResp
        public SingleResp[] Responses { get; }
        public RespID ResponderId { get; }
        public DateTime ProducedAt { get; }
        public bool Verify(AsymmetricKeyParameter publicKey)
        public X509Certificate[] GetCerts()
        public IStore<X509Certificate> GetCertificates()
    // SingleResp.GetCertStatus() returns null for "good", or a RevokedStatus /
    // UnknownStatus instance. BasicOcspRespGenerator and OCSPRespGenerator
    // build responses.

    // namespace CodeBrix.Cryptography.Tsp
    public class TimeStampRequestGenerator
        public TimeStampRequestGenerator()
        public TimeStampRequestGenerator(IDigestAlgorithmFinder digestAlgorithmFinder)
        public void SetReqPolicy(string reqPolicy)
        public void SetCertReq(bool certReq)
        public virtual void AddExtension(DerObjectIdentifier oid, bool critical,
                    Asn1Encodable extValue)
        public TimeStampRequest Generate(string digestAlgorithm, byte[] digest)
        public TimeStampRequest Generate(string digestAlgorithmOid, byte[] digest,
                    BigInteger nonce)
        public virtual TimeStampRequest Generate(AlgorithmIdentifier digestAlgorithm,
                    byte[] digest)

    public class TimeStampResponse
        public TimeStampResponse(byte[] resp)
        public TimeStampResponse(Stream input)
        public int Status { get; }
        public string GetStatusString()
        public PkiFailureInfo GetFailInfo()
        public TimeStampToken TimeStampToken { get; }
        public void Validate(TimeStampRequest request)
        public byte[] GetEncoded()
    // TimeStampResponseGenerator and TimeStampTokenGenerator build responses;
    // TSPAlgorithms holds the permitted digest OIDs.

CMP (RFC 4210) and CRMF (RFC 4211) follow the same builder idiom:
ProtectedPkiMessageBuilder / ProtectedPkiMessage / GeneralPkiMessage and
CertificateConfirmationContentBuilder in CodeBrix.Cryptography.Cmp;
CertificateRequestMessageBuilder / CertificateRequestMessage,
CertificateReqMessagesBuilder, CertificateRepMessageBuilder,
EncryptedValueBuilder, PKMacBuilder and PkiArchiveControlBuilder in
CodeBrix.Cryptography.Crmf.


ASN.1
-----

    // namespace CodeBrix.Cryptography.Asn1
    public abstract class Asn1Encodable : IAsn1Convertible
        public const string Ber = "BER", Der = "DER", DL = "DL"
        public byte[] GetEncoded()                  // BER
        public byte[] GetEncoded(string encoding)   // Asn1Encodable.Der
        public byte[] GetDerEncoded()
        public virtual void EncodeTo(Stream output)
        public virtual void EncodeTo(Stream output, string encoding)
        public abstract Asn1Object ToAsn1Object();

    public abstract class Asn1Object : Asn1Encodable
        public static Asn1Object FromByteArray(byte[] data)
        public static Asn1Object FromStream(Stream inStr)

Every specification structure is a class with a static GetInstance(object) (and
usually GetInstance(Asn1TaggedObject, bool), GetOptional and GetTagged)
factory: Asn1Sequence, Asn1Set, DerInteger, DerBitString, DerOctetString,
DerObjectIdentifier, DerUtf8String, DerPrintableString, DerIA5String,
DerGeneralizedTime, DerUtcTime, DerNull, DerBoolean, DerTaggedObject, and the
per-spec structures (X509CertificateStructure, TbsCertificateStructure,
AlgorithmIdentifier, SubjectPublicKeyInfo, PrivateKeyInfo, CertificateList,
ContentInfo, ...). Asn1Dump in Asn1.Utilities pretty-prints a parsed object.

OID constant holders, one per specification body: PkcsObjectIdentifiers,
X509ObjectIdentifiers, X9ObjectIdentifiers, NistObjectIdentifiers,
SecObjectIdentifiers, EdECObjectIdentifiers, OiwObjectIdentifiers,
CmsObjectIdentifiers, CryptoProObjectIdentifiers, TeleTrusTObjectIdentifiers,
GMObjectIdentifiers, KisaObjectIdentifiers, NttObjectIdentifiers,
RosstandartObjectIdentifiers, MiscObjectIdentifiers, IsaraObjectIdentifiers,
BCObjectIdentifiers and others, each in its own Asn1.* sub-namespace.

Encoders live in CodeBrix.Cryptography.Utilities.Encoders:

    public static class Hex
        public static string ToHexString(byte[] data)
        public static string ToHexString(byte[] data, bool upperCase)
        public static byte[] Encode(byte[] data)
        public static byte[] Decode(byte[] data)
        public static byte[] Decode(string data)
        public static byte[] DecodeStrict(string str)

    public static class Base64
        public static string ToBase64String(byte[] data)
        public static byte[] Encode(byte[] data)
        public static byte[] Decode(byte[] data)
        public static byte[] Decode(string data)
    // UrlBase64 is the URL-safe variant.


POST-QUANTUM AND KEM
--------------------

ML-KEM, ML-DSA and SLH-DSA are in the main Crypto namespaces rather than under
Pqc:

    // namespace CodeBrix.Cryptography.Crypto.Parameters
    public sealed class MLKemParameters
        public static readonly MLKemParameters ml_kem_512, ml_kem_768, ml_kem_1024
        public string Name { get; }
    // MLDsaParameters and SlhDsaParameters follow the same static-instance shape.

    // namespace CodeBrix.Cryptography.Crypto.Generators
    public class MLKemKeyPairGenerator : IAsymmetricCipherKeyPairGenerator
        // takes an MLKemKeyGenerationParameters:
        public void Init(KeyGenerationParameters parameters)
        public AsymmetricCipherKeyPair GenerateKeyPair()
    // MLDsaKeyPairGenerator and SlhDsaKeyPairGenerator likewise.

    // namespace CodeBrix.Cryptography.Crypto.Kems
    public sealed class MLKemEncapsulator : IKemEncapsulator
        public MLKemEncapsulator(MLKemParameters parameters)
        public void Init(ICipherParameters parameters)         // recipient public key
        public int EncapsulationLength { get; }
        public int SecretLength { get; }
        public void Encapsulate(byte[] encBuf, int encOff, int encLen,
                                byte[] secBuf, int secOff, int secLen)
        public void Encapsulate(Span<byte> encapsulation, Span<byte> secret)
    // MLKemDecapsulator is the peer, with Decapsulate(...).

    // namespace CodeBrix.Cryptography.Crypto.Signers
    public sealed class MLDsaSigner : ISigner
        public MLDsaSigner(MLDsaParameters parameters, bool deterministic)
    // HashMLDsaSigner, SlhDsaSigner and HashSlhDsaSigner likewise.

The remaining NIST candidates live under CodeBrix.Cryptography.Pqc.Crypto.* —
Bike, Cmce, Crystals.Dilithium, Falcon, Frodo, Hqc, Lms, Ntru, NtruPrime,
Picnic, Saber, SphincsPlus — each with its own *Parameters, *KeyPairGenerator,
*KemGenerator / *KemExtractor or *Signer types, and Pqc.Asn1 for their
encodings. Re-read the EXPERIMENTAL warning near the top of this file before
using any of them.


ERROR MODEL
-----------

There is no single exception base — each layer has its own:

    CodeBrix.Cryptography.Crypto
        CryptoException                base for algorithm-layer failures
        InvalidCipherTextException     AEAD tag mismatch, bad padding, bad
                                       RSA block — treat as "authentication or
                                       decryption failed", never ignore
        DataLengthException            input/output buffer wrong size
        OutputLengthException          output buffer too small
        MaxBytesExceededException      stream cipher used past its limit
    CodeBrix.Cryptography.Asn1
        Asn1Exception, Asn1ParsingException
    CodeBrix.Cryptography.Security
        GeneralSecurityException       base for the facade
        SecurityUtilityException       unknown algorithm name or OID
        InvalidKeyException, InvalidParameterException, KeyException,
        SignatureException, EncryptionException, PasswordException
    CodeBrix.Cryptography.Security.Certificates
        CertificateException, CertificateEncodingException,
        CertificateParsingException, CertificateExpiredException,
        CertificateNotYetValidException, CrlException
    CodeBrix.Cryptography.Cms          CmsException, CmsStreamException,
                                       CmsVerifierCertificateNotValidException
    CodeBrix.Cryptography.Pkcs         PkcsException, PkcsIOException
    CodeBrix.Cryptography.Bcpg.OpenPgp PgpException, PgpDataValidationException,
                                       PgpKeyValidationException
    CodeBrix.Cryptography.Tls          TlsFatalAlert, TlsTimeoutException,
                                       TlsNoCloseNotifyException
    CodeBrix.Cryptography.Ocsp         OcspException
    CodeBrix.Cryptography.Tsp          TspException, TspValidationException
    CodeBrix.Cryptography.Pkix         PkixCertPathBuilderException,
                                       PkixCertPathValidatorException,
                                       PkixNameConstraintValidatorException
    CodeBrix.Cryptography.Cmp          CmpException
    CodeBrix.Cryptography.Crmf         CrmfException
    CodeBrix.Cryptography.OpenSsl      PemException, PasswordException,
                                       EncryptionException

Plus the ordinary ArgumentException / ArgumentNullException /
InvalidOperationException / IOException / EndOfStreamException for misuse and
truncated input.


RUNTIME CONFIGURATION
---------------------

    // namespace CodeBrix.Cryptography.Utilities
    public static class Properties
        public static string GetProperty(string name)
        public static string GetProperty(string name, string defaultValue)
        public static bool GetBoolean(string propertyName, bool defaultValue)
        public static int GetInt32(string propertyName, int defaultValue)
        public static long GetInt64(string propertyName, long defaultValue)
        public static void SetThreadProperty(string name, string value)
        public static void SetThreadBoolean(string propertyName, bool propertyValue)
        public static void SetThreadInt32(string propertyName, int propertyValue)
        public static bool RemoveThreadProperty(string name)
        public static void ClearThreadProperties()
        public static void WithThreadProperty(string name, string value,
                    Action action)

Evaluation order is thread properties first, then environment variables. The
API can read environment variables but never modifies them.

The property names are public static readonly string fields on Properties, and
they KEEP THEIR UPSTREAM SPELLING deliberately, so an application already
configured for the upstream package keeps working after swapping in this one:

    Properties.Asn1MaxDepth              "Org.BouncyCastle.Asn1.MaxDepth"
    Properties.Asn1MaxLimit              "Org.BouncyCastle.Asn1.MaxLimit"
    Properties.Asn1AllowUnsafeInteger    "Org.BouncyCastle.Asn1.AllowUnsafeInteger"
    Properties.RsaMaxSize                "Org.BouncyCastle.Rsa.MaxSize"
    Properties.RsaMaxMRTests             "Org.BouncyCastle.Rsa.MaxMRTests"
    Properties.RsaAllowUnsafeModulus     "Org.BouncyCastle.Rsa.AllowUnsafeModulus"
    Properties.DsaMaxSize                "Org.BouncyCastle.Dsa.MaxSize"
    Properties.DHMaxSize                 "Org.BouncyCastle.DH.MaxSize"
    Properties.ECFpMaxSize               "Org.BouncyCastle.EC.Fp_MaxSize"
    Properties.ECF2mMaxSize              "Org.BouncyCastle.EC.F2m_MaxSize"
    Properties.ECFpCertainty             "Org.BouncyCastle.EC.Fp_Certainty"
    Properties.Pkcs12MaxIterationCount   "Org.BouncyCastle.Pkcs12.MaxIterationCount"
    Properties.Pkcs12IgnoreUselessPassword
                              "Org.BouncyCastle.Pkcs12.IgnoreUselessPassword"
    Properties.PbeMaxIterationCount      "Org.BouncyCastle.Pbe.MaxIterationCount"
    Properties.PbeMaxScryptMemory        "Org.BouncyCastle.Pbe.MaxScryptMemory"
    Properties.Argon2MaxMemoryExp        "Org.BouncyCastle.Argon2.MaxMemoryExp"
    Properties.Argon2MaxPasses           "Org.BouncyCastle.Argon2.MaxPasses"
    Properties.Argon2MaxParallelism      "Org.BouncyCastle.Argon2.MaxParallelism"
    Properties.Pkcs1NotStrict            "Org.BouncyCastle.Pkcs1.NotStrict"
    Properties.PKMacMaxIterationCount    "Org.BouncyCastle.PKMac.MaxIterationCount"
    Properties.CmsAllowLenientRsaPkcs1   "Org.BouncyCastle.Cms.AllowLenientRsaPkcs1"
    Properties.FpeDisable                "Org.BouncyCastle.Fpe.Disable"
    Properties.FpeDisableFf1             "Org.BouncyCastle.Fpe.Disable_Ff1"
    Properties.X509MaxPolicyNodes        "Org.BouncyCastle.X509.MaxPolicyNodes"
    Properties.X509AllowNonDerTbsCertificate
                              "Org.BouncyCastle.X509.Allow_Non-DER_TBSCert"
    Properties.X509AllowLenientRfc822Name
                              "Org.BouncyCastle.X509.AllowLenientRfc822Name"
    Properties.X509AllowEmptyIssuerCert  "Org.BouncyCastle.X509.AllowEmptyIssuerCert"
    Properties.X509Sgp22NameConstraints  "Org.BouncyCastle.X509.Sgp22NameConstraints"
    Properties.X509AllowLenientIPAddressMask
                              "Org.BouncyCastle.X509.AllowLenientIPAddressMask"

Do NOT "fix" these strings to say CodeBrix. Reference the field rather than
retyping the literal, and the spelling can never drift. A couple of the same
names are also exposed on the class that uses them:
Pkcs1Encoding.StrictLengthEnabledProperty and
Pkcs12Store.IgnoreUselessPasswordProperty.


COMPLETE EXAMPLES
=================

Every example below is a complete, self-contained program body (top-level
statements or a Main). Each compiles against the package with no other
dependencies.


EXAMPLE 1 — AES-256-GCM encrypt and decrypt
-------------------------------------------

    using System;
    using System.Text;
    using CodeBrix.Cryptography.Crypto;
    using CodeBrix.Cryptography.Crypto.Modes;
    using CodeBrix.Cryptography.Crypto.Parameters;
    using CodeBrix.Cryptography.Security;

    var random = new SecureRandom();

    byte[] key = new byte[32];        // AES-256
    byte[] nonce = new byte[12];      // 96-bit nonce; NEVER reuse with one key
    random.NextBytes(key);
    random.NextBytes(nonce);

    byte[] plaintext = Encoding.UTF8.GetBytes("attack at dawn");
    byte[] associatedData = Encoding.UTF8.GetBytes("message-id: 42");

    // Encrypt — the 128-bit tag is appended to the ciphertext.
    var encryptor = new GcmBlockCipher(AesUtilities.CreateEngine());
    encryptor.Init(forEncryption: true,
        new AeadParameters(new KeyParameter(key), 128, nonce, associatedData));

    byte[] ciphertext = new byte[encryptor.GetOutputSize(plaintext.Length)];
    int written = encryptor.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
    written += encryptor.DoFinal(ciphertext, written);

    // Decrypt — DoFinal throws InvalidCipherTextException if the tag is wrong.
    var decryptor = new GcmBlockCipher(AesUtilities.CreateEngine());
    decryptor.Init(forEncryption: false,
        new AeadParameters(new KeyParameter(key), 128, nonce, associatedData));

    byte[] recovered = new byte[decryptor.GetOutputSize(written)];
    int n = decryptor.ProcessBytes(ciphertext, 0, written, recovered, 0);
    try
    {
        n += decryptor.DoFinal(recovered, n);
        Console.WriteLine(Encoding.UTF8.GetString(recovered, 0, n));  // attack at dawn
    }
    catch (InvalidCipherTextException)
    {
        Console.WriteLine("authentication failed - do not use the plaintext");
    }


EXAMPLE 2 — RSA key generation, signing and verification
--------------------------------------------------------

    using System;
    using System.Text;
    using CodeBrix.Cryptography.Crypto;
    using CodeBrix.Cryptography.Crypto.Generators;
    using CodeBrix.Cryptography.Pkcs;
    using CodeBrix.Cryptography.Security;
    using CodeBrix.Cryptography.X509;

    var random = new SecureRandom();

    var generator = new RsaKeyPairGenerator();
    generator.Init(new KeyGenerationParameters(random, 3072));
    AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();

    byte[] data = Encoding.UTF8.GetBytes("the message to sign");

    ISigner signer = SignerUtilities.InitSigner(
        "SHA256withRSA", forSigning: true, pair.Private, random);
    signer.BlockUpdate(data, 0, data.Length);
    byte[] signature = signer.GenerateSignature();

    ISigner verifier = SignerUtilities.InitSigner(
        "SHA256withRSA", forSigning: false, pair.Public, null);
    verifier.BlockUpdate(data, 0, data.Length);
    Console.WriteLine(verifier.VerifySignature(signature));      // True

    // Round-trip the keys through the standard encodings.
    byte[] pkcs8 = PrivateKeyInfoFactory
        .CreatePrivateKeyInfo(pair.Private).GetEncoded();
    byte[] spki = SubjectPublicKeyInfoFactory
        .CreateSubjectPublicKeyInfo(pair.Public).GetEncoded();

    var reloadedPublic = PublicKeyFactory.CreateKey(spki);
    ISigner verifier2 = SignerUtilities.InitSigner(
        "SHA256withRSA", forSigning: false, reloadedPublic, null);
    verifier2.BlockUpdate(data, 0, data.Length);
    Console.WriteLine(verifier2.VerifySignature(signature));      // True
    Console.WriteLine(pkcs8.Length > 0);                          // True

Signature mechanism names accepted by SignerUtilities include
"SHA256withRSA", "SHA384withRSA", "SHA512withRSA",
"SHA256withRSAandMGF1" (PSS), "SHA256withECDSA", "SHA256withDSA",
"Ed25519", "Ed448", "SHA256withSM2", "ML-DSA", "SLH-DSA".


EXAMPLE 3 — EC key generation, ECDH and a derived AES key
----------------------------------------------------------

    using System;
    using CodeBrix.Cryptography.Asn1.X9;
    using CodeBrix.Cryptography.Crypto.Agreement;
    using CodeBrix.Cryptography.Crypto.Digests;
    using CodeBrix.Cryptography.Crypto.Generators;
    using CodeBrix.Cryptography.Crypto.Parameters;
    using CodeBrix.Cryptography.Math;
    using CodeBrix.Cryptography.Security;
    using CodeBrix.Cryptography.Utilities;
    using CodeBrix.Cryptography.Utilities.Encoders;

    var random = new SecureRandom();

    var keyGenParams = new ECKeyGenerationParameters(
        ECNamedCurveTable.GetOid("secp256r1"), random);

    var generator = new ECKeyPairGenerator("ECDH");
    generator.Init(keyGenParams);

    var alice = generator.GenerateKeyPair();
    var bob = generator.GenerateKeyPair();

    var aliceAgreement = new ECDHBasicAgreement();
    aliceAgreement.Init(alice.Private);
    BigInteger aliceZ = aliceAgreement.CalculateAgreement(bob.Public);

    var bobAgreement = new ECDHBasicAgreement();
    bobAgreement.Init(bob.Private);
    BigInteger bobZ = bobAgreement.CalculateAgreement(alice.Public);

    // Fixed-width encoding: never use BigInteger.ToByteArray for this.
    byte[] aliceShared = BigIntegers.AsUnsignedByteArray(
        aliceAgreement.GetFieldSize(), aliceZ);
    byte[] bobShared = BigIntegers.AsUnsignedByteArray(
        bobAgreement.GetFieldSize(), bobZ);
    Console.WriteLine(Arrays.AreEqual(aliceShared, bobShared));        // True

    // The raw agreement is NOT a key. Run it through a KDF.
    var hkdf = new HkdfBytesGenerator(new Sha256Digest());
    hkdf.Init(new HkdfParameters(aliceShared, salt: null,
        info: System.Text.Encoding.UTF8.GetBytes("aes-256-gcm session key")));
    byte[] sessionKey = new byte[32];
    hkdf.GenerateBytes(sessionKey, 0, sessionKey.Length);
    Console.WriteLine(Hex.ToHexString(sessionKey));

    // X25519 is the same idea with a raw agreement.
    var x25519Private = new X25519PrivateKeyParameters(random);
    var x25519Public = x25519Private.GeneratePublicKey();
    var x25519Peer = new X25519PrivateKeyParameters(random);

    var raw = new X25519Agreement();
    raw.Init(x25519Private);
    byte[] rawShared = new byte[raw.AgreementSize];
    raw.CalculateAgreement(x25519Peer.GeneratePublicKey(), rawShared, 0);
    Console.WriteLine(rawShared.Length);                              // 32

(HkdfBytesGenerator is in CodeBrix.Cryptography.Crypto.Generators and
HkdfParameters in CodeBrix.Cryptography.Crypto.Parameters — both already
covered by the usings above.)


EXAMPLE 4 — PEM: save a key pair, load it back
-----------------------------------------------

    using System;
    using System.IO;
    using CodeBrix.Cryptography.Crypto;
    using CodeBrix.Cryptography.Crypto.Generators;
    using CodeBrix.Cryptography.OpenSsl;
    using CodeBrix.Cryptography.Security;

    var random = new SecureRandom();
    var generator = new RsaKeyPairGenerator();
    generator.Init(new KeyGenerationParameters(random, 2048));
    AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();

    // Write an unencrypted PKCS#8 private key and a SubjectPublicKeyInfo.
    var writer = new StringWriter();
    using (var pemWriter = new PemWriter(writer))
    {
        pemWriter.WriteObject(new Pkcs8Generator(pair.Private));   // "PRIVATE KEY"
        pemWriter.WriteObject(pair.Public);                        // "PUBLIC KEY"
    }
    File.WriteAllText("keys.pem", writer.ToString());

    // Write an ENCRYPTED PKCS#8 private key instead.
    var encWriter = new StringWriter();
    using (var pemWriter = new PemWriter(encWriter))
    {
        var pkcs8 = new Pkcs8Generator(pair.Private, Pkcs8Generator.PbeSha1_3DES)
        {
            Password = "correct horse battery staple".ToCharArray(),
            SecureRandom = random,
            IterationCount = 100_000,
        };
        pemWriter.WriteObject(pkcs8);            // "ENCRYPTED PRIVATE KEY"
    }
    File.WriteAllText("key-encrypted.pem", encWriter.ToString());

    // Read them back. ReadObject() returns object; the runtime type depends on
    // the PEM label (see the mapping table above).
    using (var reader = new StringReader(File.ReadAllText("keys.pem")))
    {
        var pemReader = new PemReader(reader);

        object first = pemReader.ReadObject();
        var privateKey = (AsymmetricKeyParameter)first;            // PKCS#8 -> key
        object second = pemReader.ReadObject();
        var publicKey = (AsymmetricKeyParameter)second;

        Console.WriteLine(privateKey.IsPrivate);                   // True
        Console.WriteLine(publicKey.IsPrivate);                    // False
    }

    // An encrypted key needs an IPasswordFinder.
    sealed class FixedPassword : IPasswordFinder
    {
        private readonly char[] m_password;
        public FixedPassword(string password) { m_password = password.ToCharArray(); }
        public char[] GetPassword() => (char[])m_password.Clone();
    }

    using (var reader = new StringReader(File.ReadAllText("key-encrypted.pem")))
    {
        var pemReader = new PemReader(reader,
            new FixedPassword("correct horse battery staple"));
        var decrypted = (AsymmetricKeyParameter)pemReader.ReadObject();
        Console.WriteLine(decrypted.IsPrivate);                    // True
    }

A legacy OpenSSL "-----BEGIN RSA PRIVATE KEY-----" file returns an
AsymmetricCipherKeyPair, not an AsymmetricKeyParameter. Handle both:

    object obj = pemReader.ReadObject();
    AsymmetricKeyParameter privateKey = obj switch
    {
        AsymmetricCipherKeyPair kp => kp.Private,
        AsymmetricKeyParameter k when k.IsPrivate => k,
        _ => throw new InvalidOperationException("not a private key: " + obj?.GetType())
    };


EXAMPLE 5 — self-signed X.509 certificate with extensions
----------------------------------------------------------

    using System;
    using System.IO;
    using CodeBrix.Cryptography.Asn1.X509;
    using CodeBrix.Cryptography.Crypto;
    using CodeBrix.Cryptography.Crypto.Generators;
    using CodeBrix.Cryptography.Crypto.Operators;
    using CodeBrix.Cryptography.Math;
    using CodeBrix.Cryptography.OpenSsl;
    using CodeBrix.Cryptography.Security;
    using CodeBrix.Cryptography.X509;

    var random = new SecureRandom();

    var keyPairGenerator = new RsaKeyPairGenerator();
    keyPairGenerator.Init(new KeyGenerationParameters(random, 3072));
    AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

    var name = new X509Name("CN=example.test, O=Acme, C=US");

    var certificateGenerator = new X509V3CertificateGenerator();
    certificateGenerator.SetSerialNumber(BigInteger.ProbablePrime(120, random));
    certificateGenerator.SetIssuerDN(name);
    certificateGenerator.SetSubjectDN(name);
    certificateGenerator.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
    certificateGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
    certificateGenerator.SetPublicKey(keyPair.Public);

    certificateGenerator.AddExtension(X509Extensions.BasicConstraints, true,
        new BasicConstraints(cA: false));
    certificateGenerator.AddExtension(X509Extensions.KeyUsage, true,
        new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
    certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, false,
        new ExtendedKeyUsage(KeyPurposeID.id_kp_serverAuth));
    certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false,
        new GeneralNames(new GeneralName(GeneralName.DnsName, "example.test")));

    var signatureFactory = new Asn1SignatureFactory(
        "SHA256WITHRSA", keyPair.Private, random);
    X509Certificate certificate = certificateGenerator.Generate(signatureFactory);

    certificate.CheckValidity();                    // throws if outside validity
    certificate.Verify(keyPair.Public);             // throws on a bad signature

    Console.WriteLine(certificate.SubjectDN);
    Console.WriteLine(certificate.SigAlgName);
    Console.WriteLine(certificate.SerialNumber);

    // Persist as PEM, then read it back.
    var certWriter = new StringWriter();
    using (var pemWriter = new PemWriter(certWriter))
    {
        pemWriter.WriteObject(certificate);                        // "CERTIFICATE"
    }
    File.WriteAllText("cert.pem", certWriter.ToString());

    var parsed = new X509CertificateParser()
        .ReadCertificate(File.ReadAllBytes("cert.pem"));
    Console.WriteLine(parsed.SubjectDN.Equivalent(certificate.SubjectDN));   // True


EXAMPLE 6 — OpenPGP: encrypt to a public key and decrypt
---------------------------------------------------------

Modelled on this package's own PGP round-trip test.

    using System;
    using System.IO;
    using System.Text;
    using CodeBrix.Cryptography.Asn1.Sec;
    using CodeBrix.Cryptography.Bcpg;
    using CodeBrix.Cryptography.Bcpg.OpenPgp;
    using CodeBrix.Cryptography.Crypto;
    using CodeBrix.Cryptography.Crypto.Parameters;
    using CodeBrix.Cryptography.Security;

    var random = new SecureRandom();
    byte[] message = Encoding.UTF8.GetBytes("hello world!");

    // A throwaway ECDH key pair. In real use, load a PgpPublicKeyRing /
    // PgpSecretKeyRing instead and call GetPublicKey() / ExtractPrivateKey().
    IAsymmetricCipherKeyPairGenerator keyGen =
        GeneratorUtilities.GetKeyPairGenerator("ECDH");
    keyGen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, random));
    var pgpKeyPair = new PgpKeyPair(
        PublicKeyAlgorithmTag.ECDH, keyGen.GenerateKeyPair(), DateTime.UtcNow);

    // 1. Wrap the payload in a literal-data packet.
    var literalOut = new MemoryStream();
    var literalGen = new PgpLiteralDataGenerator();
    using (Stream lOut = literalGen.Open(literalOut, PgpLiteralDataGenerator.Utf8,
               PgpLiteralData.Console, message.Length, DateTime.UtcNow))
    {
        lOut.Write(message, 0, message.Length);
    }
    byte[] literal = literalOut.ToArray();

    // 2. Encrypt it to the recipient's public key, with an integrity packet.
    var encryptedOut = new MemoryStream();
    var encGen = new PgpEncryptedDataGenerator(
        SymmetricKeyAlgorithmTag.Aes256, withIntegrityPacket: true, random);
    encGen.AddMethod(pgpKeyPair.PublicKey);
    using (Stream cOut = encGen.Open(encryptedOut, literal.Length))
    {
        cOut.Write(literal, 0, literal.Length);
    }
    byte[] encrypted = encryptedOut.ToArray();

    // 3. Optionally ASCII-armor it.
    var armoredOut = new MemoryStream();
    using (var armor = new ArmoredOutputStream(armoredOut))
    {
        armor.Write(encrypted, 0, encrypted.Length);
    }
    Console.WriteLine(Encoding.ASCII.GetString(armoredOut.ToArray()));

    // 4. Decrypt. GetDecoderStream strips armor if present.
    Stream input = PgpUtilities.GetDecoderStream(
        new MemoryStream(armoredOut.ToArray()));
    var factory = new PgpObjectFactory(input);
    var encList = (PgpEncryptedDataList)factory.NextPgpObject();
    var encData = (PgpPublicKeyEncryptedData)encList[0];

    using (Stream clear = encData.GetDataStream(pgpKeyPair.PrivateKey))
    {
        var literalFactory = new PgpObjectFactory(clear);
        var literalData = (PgpLiteralData)literalFactory.NextPgpObject();
        using (var reader = new StreamReader(
                   literalData.GetInputStream(), Encoding.UTF8))
        {
            Console.WriteLine(reader.ReadToEnd());          // hello world!
        }
    }

With a real key ring, steps 2 and 4 become:

    var pubRing = new PgpPublicKeyRing(
        PgpUtilities.GetDecoderStream(File.OpenRead("recipient-pub.asc")));
    encGen.AddMethod(pubRing.GetPublicKey());

    var secRing = new PgpSecretKeyRing(
        PgpUtilities.GetDecoderStream(File.OpenRead("my-sec.asc")));
    PgpPrivateKey privateKey = secRing
        .GetSecretKey(encData.KeyId)
        .ExtractPrivateKey(passphrase.ToCharArray());


EXAMPLE 7 — CMS: sign, then verify
-----------------------------------

    using System;
    using System.Linq;
    using System.Text;
    using CodeBrix.Cryptography.Cms;
    using CodeBrix.Cryptography.Utilities.Collections;
    using CodeBrix.Cryptography.X509;

    // 'keyPair' and 'certificate' come from EXAMPLE 5.
    byte[] data = Encoding.UTF8.GetBytes("the document to sign");

    var generator = new CmsSignedDataGenerator();
    generator.AddSigner(keyPair.Private, certificate, CmsSignedGenerator.DigestSha256);
    generator.AddCertificates(CollectionUtilities.CreateStore(new[] { certificate }));

    CmsSignedData signed = generator.Generate(
        new CmsProcessableByteArray(data), encapsulate: true);
    byte[] encoded = signed.GetEncoded();

    // Verify.
    var reloaded = new CmsSignedData(encoded);
    var certStore = reloaded.GetCertificates();

    foreach (SignerInformation signer in reloaded.GetSignerInfos().GetSigners())
    {
        X509Certificate signerCert = certStore
            .EnumerateMatches(signer.SignerID)
            .First();
        Console.WriteLine(signer.Verify(signerCert));       // True
    }

For a detached signature, pass encapsulate: false and reconstruct with
new CmsSignedData(new CmsProcessableByteArray(data), encoded).


MINIMUM VIABLE PROJECT
======================

MyCryptoApp.csproj

    <Project Sdk="Microsoft.NET.Sdk">

      <PropertyGroup>
        <OutputType>Exe</OutputType>
        <TargetFramework>net10.0</TargetFramework>
        <Nullable>disable</Nullable>
      </PropertyGroup>

      <ItemGroup>
        <PackageReference Include="CodeBrix.Cryptography.MitLicenseForever" />
      </ItemGroup>

    </Project>

(Use Version="..." on the PackageReference, or central package management, to
pin a version — resolve the current one from nuget.org at the time you add it.)

Program.cs

    using System;
    using System.Text;
    using CodeBrix.Cryptography.Crypto;
    using CodeBrix.Cryptography.Crypto.Digests;
    using CodeBrix.Cryptography.Crypto.Modes;
    using CodeBrix.Cryptography.Crypto.Parameters;
    using CodeBrix.Cryptography.Security;
    using CodeBrix.Cryptography.Utilities.Encoders;

    internal static class Program
    {
        private static void Main()
        {
            var random = new SecureRandom();

            byte[] key = SecureRandom.GetNextBytes(random, 32);
            byte[] nonce = SecureRandom.GetNextBytes(random, 12);
            byte[] plaintext = Encoding.UTF8.GetBytes("hello, cryptography");

            var cipher = new GcmBlockCipher(AesUtilities.CreateEngine());
            cipher.Init(forEncryption: true,
                new AeadParameters(new KeyParameter(key), 128, nonce));

            byte[] ciphertext = new byte[cipher.GetOutputSize(plaintext.Length)];
            int n = cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
            n += cipher.DoFinal(ciphertext, n);

            Console.WriteLine("ciphertext+tag: " + Hex.ToHexString(ciphertext, 0, n));
            Console.WriteLine("sha-256:        " +
                Hex.ToHexString(DigestUtilities.CalculateDigest("SHA-256", plaintext)));
            Console.WriteLine("aes-ni:         " + AesUtilities.IsHardwareAccelerated);
        }
    }

Nothing else is needed — no initialisation call, no provider registration, no
native asset copy step.


PERFORMANCE TIPS
================

  * Reuse one SecureRandom. Constructing one seeds a DRBG; constructing many in
    a loop is pure overhead. Pass it into the generators and factories that
    accept one, or use CryptoServicesRegistrar.GetSecureRandom().

  * Use AesUtilities.CreateEngine() rather than `new AesEngine()`. It returns
    the AES-NI-backed AesEngine_X86 when the CPU supports it; AesUtilities
    .IsHardwareAccelerated tells you which you got. The same idea applies to
    GCM, whose multiplier picks up carry-less multiply automatically, and to
    Blake2b/Blake2s/Haraka, which have x86 variants selected internally.

  * Reuse initialised cipher, digest, MAC and signer instances across
    operations and call Reset() between them, rather than allocating a new one
    per message. They are NOT thread-safe, so use one per thread (or a pool),
    never one shared instance.

  * Prefer the Span<byte>/ReadOnlySpan<byte> overloads (ProcessBytes,
    BlockUpdate, DoFinal, GetEncoded targets) on hot paths; they avoid the
    intermediate arrays the byte[]-plus-offset overloads need.

  * Size output buffers with GetOutputSize()/GetUpdateOutputSize() once, and
    write into a single buffer, instead of concatenating the byte[]-returning
    overloads.

  * RSA key generation at 3072 bits and above is measured in seconds; do it
    once, off the request path, and persist the key. RSA private-key operations
    should use RSABlindedEngine, which is both safer and only marginally
    slower.

  * Password KDFs are slow ON PURPOSE. Tune the work factor (Argon2 memory and
    iterations, scrypt N/r/p, PBKDF2 iteration count) to your hardware budget
    and measure; do not raise them blindly and do not lower them to "fix" a
    slow login. Argon2BytesGenerator(TaskFactory) parallelises the lanes.

  * For large payloads use the streaming APIs rather than materialising
    everything: CipherStream / DigestStream / MacStream / SignerStream
    (Crypto.IO), CmsSignedDataStreamGenerator / CmsSignedDataParser,
    CmsEnvelopedDataStreamGenerator / CmsEnvelopedDataParser, and the PGP
    generators' Open(Stream, byte[] buffer) overloads.

  * Reuse a single X509CertificateParser instance when reading many
    certificates from one stream — it keeps the PKCS#7 parse state between
    calls, and ParseCertificates(Stream) enumerates lazily.

  * Path validation with revocation checking (PkixParameters.IsRevocationEnabled
    = true) is the expensive part of PKIX. Cache CRLs in the IStore<X509Crl>
    you hand to AddStoreCrl rather than re-fetching per validation.

  * The x86 intrinsic paths are probed once through
    CodeBrix.Cryptography.Runtime.Intrinsics.X86; there is no per-call
    detection cost and nothing to configure.


COMMON PITFALLS TO AVOID
========================

  * InvalidCipherTextException from an AEAD DoFinal IS the authentication
    failure. Never catch-and-continue with the partially written output buffer;
    treat the whole message as forged and discard the plaintext.

  * NEVER reuse a (key, nonce) pair with GCM, CCM, EAX, OCB or
    ChaCha20-Poly1305. Nonce reuse with a counter-mode AEAD leaks the
    authentication key, not just the plaintext. Generate the nonce randomly per
    message (12 bytes for GCM) or use a strictly increasing counter you persist.
    GcmSivBlockCipher is the nonce-misuse-resistant option if you cannot
    guarantee uniqueness.

  * AeadParameters takes macSize in BITS (128, not 16), and
    PbeParametersGenerator.GenerateDerivedParameters takes keySize/ivSize in
    BITS too. Passing bytes silently produces a much weaker result.

  * Do NOT rename the runtime configuration keys. They deliberately keep the
    "Org.BouncyCastle.*" spelling so that an application already configured for
    the upstream package keeps working. Reference the
    Utilities.Properties.<Name> field instead of retyping the string.

  * Key-format confusion is the most common integration bug in this library:
      - PrivateKeyFactory.CreateKey expects a PKCS#8 PrivateKeyInfo encoding,
        PublicKeyFactory.CreateKey expects a SubjectPublicKeyInfo encoding.
        Feeding one to the other throws rather than misbehaving, but the error
        rarely says "wrong format".
      - PemReader.ReadObject() returns AsymmetricCipherKeyPair for the legacy
        "RSA/DSA/EC PRIVATE KEY" labels and AsymmetricKeyParameter for the
        PKCS#8 "PRIVATE KEY" label. Handle both (see EXAMPLE 4).
      - AsymmetricKeyParameter.IsPrivate is the cheap way to tell which half of
        a pair you are holding; Init(forSigning: true, publicKey) fails late.

  * Asn1SignatureFactory and Asn1VerifierFactory live in
    CodeBrix.Cryptography.Crypto.Operators, NOT CodeBrix.Cryptography.Operators.
    The latter namespace exists and holds different types.

  * Raw RSA cannot encrypt more than GetInputBlockSize() bytes, and raw
    RsaEngine has no padding at all. Always wrap it: OaepEncoding for
    encryption, and prefer RSABlindedEngine over RsaEngine for private-key
    operations.

  * An ECDH/X25519 agreement result is NOT a key. Run it through a KDF (HKDF,
    or the *WithKdf agreement variants) before using it. And convert an ECDH
    BigInteger with BigIntegers.AsUnsignedByteArray(fieldSize, z) — plain
    ToByteArray() gives a variable-length, possibly sign-padded encoding that
    will not match the other party's.

  * TLS certificate validation is YOUR job.
    TlsAuthentication.NotifyServerCertificate is where it happens, and an empty
    implementation accepts every certificate. Wire it to
    PkixCertPathBuilder/PkixCertPathValidator or an equivalent check.

  * X509Certificate.Verify(publicKey) only checks the signature against the key
    you hand it. It does not check validity dates (CheckValidity()), revocation
    (OCSP/CRL), name matching, or chain building. Path validation is the Pkix
    namespace's job.

  * Post-quantum algorithms are EXPERIMENTAL. Their APIs, parameter sets and
    encodings can change between releases; do not persist data or keys that
    have to survive an upgrade.

  * This library's Math.BigInteger is not System.Numerics.BigInteger, and
    Utilities.Collections.IStore<T>/ISelector<T> are not
    System.Collections interfaces. A file that needs both worlds should alias.

  * Cipher, digest, MAC, signer and generator objects are stateful and not
    thread-safe. SecureRandom is safe to share; almost nothing else is.

  * Comparing secrets with SequenceEqual or a plain loop leaks timing. Use
    CodeBrix.Cryptography.Utilities.Arrays.FixedTimeEquals or the AEAD/MAC
    verification the library already provides.

  * Do not use MD5, SHA-1, DES, RC4 or 1024-bit RSA in new work. They are all
    present because interoperability and test vectors demand them, not as
    recommendations.

  * Some members are marked [Obsolete] (older CMS generators, legacy SPHINCS+
    entry points, GcmBlockCipher's IGcmMultiplier constructor, some Ascon
    types). The compiler warning is the guidance; do not suppress it in
    consumer code, switch to the replacement it names.

  * PemWriter/PemReader wrap a TextWriter/TextReader. Flush or dispose the
    writer before reading the underlying buffer back, or you will get a
    truncated PEM block.


WHAT THIS PACKAGE DOES NOT DO
=============================

  * It does not integrate with System.Security.Cryptography as a provider.
    There is no CryptoConfig registration and no way to make
    RSA.Create()/Aes.Create() return these implementations. The bridge is
    manual and explicit: Security.DotNetUtilities converts keys and
    certificates between the two worlds.

  * It does not use OS key stores, hardware tokens, TPMs, PKCS#11 devices or
    OS certificate stores. Keys are in managed memory, and it is your job to
    zero and protect them. Trust anchors for PKIX must be supplied by you; the
    library has no notion of "the system root store".

  * It does not fetch anything over the network. There is no OCSP responder
    client, no CRL downloader, no AIA/CDP chasing, no key-server lookup and no
    HTTP at all. It builds and parses the messages; transport is yours. (TLS
    and DTLS are the exception in that they drive an existing Stream or
    DatagramTransport you provide — they never open a socket themselves.)

  * It does not do S/MIME MIME handling. CMS objects are produced and consumed;
    the multipart/signed and application/pkcs7-mime packaging around them is
    not part of the package.

  * It is not FIPS-validated. The FIPS-certified upstream distribution is a
    separate product; nothing here carries a validation certificate.

  * It ships no native code, so it also offers no hardware acceleration beyond
    the managed x86 intrinsics paths, and no GPU or AES-NI equivalent on
    non-x86 architectures (which fall back to portable managed code).

  * It has no ambient configuration file, DI registration or logging. Behaviour
    is controlled only by constructor arguments and the Utilities.Properties
    thread/environment properties.

  * It does not target netstandard or .NET Framework, and there is no
    multi-targeting to add one.


WORKING EXAMPLES ON GITHUB
==========================

The repository's test suite is the largest body of worked examples for this
package — it is the upstream suite, translated, and it exercises essentially
every feature area. Browse it at:

  https://github.com/ellisnet/CodeBrix.Cryptography/tree/main/tests/CodeBrix.Cryptography.Tests

Feature-to-test map (paths relative to that folder):

  Symmetric ciphers, modes,     Crypto/Tests/
  padding, digests, MACs        e.g. AESTest.cs, GcmSivTest.cs,
                                ChaCha20Poly1305Test.cs, CCMTest.cs,
                                CTSTest.cs, CMacTest.cs, MacTest.cs
  AES-NI / x86 intrinsics       Crypto/Tests/AesX86Test.cs
  KDFs and password hashing     Crypto/Tests/Argon2Test.cs, BCryptTest.cs,
                                SCryptTest.cs, HkdfGeneratorTest.cs,
                                Tests/PBETest.cs
  RSA                           Tests/RSATest.cs, Tests/PSSTest.cs,
                                Tests/Rsa3/, Crypto/Tests/RsaTest.cs,
                                Crypto/Tests/RSABlindedTest.cs
  DSA / EC / EdDSA / X25519     Tests/DSATest.cs, Tests/ECDSA5Test.cs,
                                Tests/NamedCurveTest.cs,
                                Math/EC/Rfc7748/Tests/, Math/EC/Rfc8032/Tests/
  Key agreement                 Tests/DHTest.cs, Tests/MqvTest.cs,
                                Crypto/Agreement/Tests/ (J-PAKE)
  Name/OID facade               Security/Tests/TestSignerUtil.cs,
                                TestDigestUtil.cs, TestMacUtil.cs,
                                TestParameterUtil.cs, TestEncodings.cs
  System.Security interop       Security/Tests/TestDotNetUtil.cs
  SecureRandom                  Security/Tests/SecureRandomTest.cs
  PEM read/write                OpenSsl/Tests/ReaderTest.cs, WriterTest.cs,
                                TestPassword.cs
  X.509 certificates and CRLs   Tests/CertTest.cs, Tests/CRL5Test.cs,
                                X509/Tests/TestCertificateGen.cs,
                                Tests/DeltaCertTest.cs
  PKCS#10 / PKCS#12             Pkcs/Tests/PKCS10Test.cs,
                                Pkcs/Tests/PKCS12StoreTest.cs,
                                Pkcs/Tests/EncryptedPrivateKeyInfoTest.cs
  PKIX path building/validation Tests/CertPathBuilderTest.cs,
                                Tests/CertPathValidatorTest.cs,
                                Tests/PkixTest.cs,
                                Tests/PkixNameConstraintsTest.cs,
                                Tests/PkixPolicyMappingTest.cs,
                                Pkix/Tests/
  CMS / S-MIME                  Cms/Tests/SignedDataTest.cs,
                                EnvelopedDataTest.cs,
                                AuthenticatedDataTest.cs,
                                CompressedDataTest.cs, Rfc4134Test.cs,
                                and the *StreamTest.cs peers
  OpenPGP                       Bcpg/OpenPgp/Tests/ — PGPRSATest.cs,
                                PgpECDHTest.cs, PgpEdDsaTest.cs,
                                PGPClearSignedSignatureTest.cs,
                                PGPArmoredTest.cs, PGPPBETest.cs,
                                PgpAeadTest.cs
  TLS and DTLS                  Tls/Tests/ — TlsProtocolTest.cs,
                                TlsClientTest.cs, TlsServerTest.cs,
                                DtlsProtocolTest.cs, TlsPskProtocolTest.cs,
                                Tls13PskProtocolTest.cs,
                                TlsProtocolNonBlockingTest.cs, and the
                                MockTls*/MockDtls* peers that show a complete
                                client and server implementation
  OCSP / TSP / CMP / CRMF       Ocsp/Tests/, Tsp/Tests/, Cmp/Tests/, Crmf/Tests/
  ASN.1                         Asn1/Tests/ and the per-spec sub-folders
  Post-quantum                  Pqc/Crypto/Tests/, Crypto/Tests/MLKemTest.cs,
                                MLDsaTest.cs, SlhDsaTest.cs
  Encoders and utilities        Utilities/UtilTests/, Utilities/IO/Pem/Tests/,
                                Utilities/Net/Tests/

Note that a subset of the suite (the post-quantum known-answer vector tests,
the LMS/HSS vectors, one Grain-128AEAD vector, and the NIST PKITS path tests)
is skipped unless an external, non-redistributable fixture set is present. That
gating is a repository concern, not a package concern — see
MAINTAINER-README.txt in the repository root if you are running the suite. The
skipped tests are still readable as examples.


QUICK REFERENCE CARD
====================

    Package         CodeBrix.Cryptography.MitLicenseForever
    Namespace root  CodeBrix.Cryptography            (no ".MitLicenseForever")
    Target          .NET 10 or later, no other dependencies
    License         MIT
    Migration       s/Org.BouncyCastle/CodeBrix.Cryptography/ in usings

    RANDOM
      new SecureRandom()                            Security
      SecureRandom.GetNextBytes(random, 32)

    AEAD ENCRYPT / DECRYPT                          Crypto.Modes
      new GcmBlockCipher(AesUtilities.CreateEngine())
      .Init(forEncryption, new AeadParameters(new KeyParameter(key), 128, nonce))
      .GetOutputSize(len) -> ProcessBytes(...) -> DoFinal(...)
      InvalidCipherTextException == authentication failure

    BLOCK CIPHER + PADDING                          Crypto.Paddings / .Modes
      new PaddedBufferedBlockCipher(
          new CbcBlockCipher(AesUtilities.CreateEngine()), new Pkcs7Padding())
      .Init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv))

    HASH / MAC                                      Crypto.Digests / .Macs
      new Sha256Digest() ; new HMac(new Sha256Digest())
      DigestUtilities.CalculateDigest("SHA-256", data)
      MacUtilities.GetMac("HMACSHA256")

    PASSWORD KDF                                    Crypto.Generators
      SCrypt.Generate(pw, salt, N, r, p, dkLen)
      BCrypt.Generate(pw, salt, cost)
      new Argon2BytesGenerator() + Argon2Parameters.Builder
      new Pkcs5S2ParametersGenerator(new Sha256Digest())   // PBKDF2
      new HkdfBytesGenerator(new Sha256Digest()) + HkdfParameters

    KEY PAIRS                                       Crypto.Generators
      new RsaKeyPairGenerator() + new KeyGenerationParameters(random, 3072)
      new ECKeyPairGenerator("ECDSA") + new ECKeyGenerationParameters(oid, random)
      new Ed25519PrivateKeyParameters(random).GeneratePublicKey()
      new X25519PrivateKeyParameters(random).GeneratePublicKey()

    SIGN / VERIFY                                   Security
      SignerUtilities.InitSigner("SHA256withRSA", forSigning, key, random)
      .BlockUpdate(data, 0, len) -> GenerateSignature() / VerifySignature(sig)

    AGREEMENT                                       Crypto.Agreement
      new ECDHBasicAgreement().Init(myPrivate).CalculateAgreement(theirPublic)
      new X25519Agreement().Init(myPrivate).CalculateAgreement(pub, buf, 0)
      ALWAYS run the result through a KDF

    KEY ENCODINGS                                   Security / Pkcs / X509
      PrivateKeyFactory.CreateKey(pkcs8Bytes)
      PublicKeyFactory.CreateKey(spkiBytes)
      PrivateKeyInfoFactory.CreatePrivateKeyInfo(key).GetEncoded()
      SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key).GetEncoded()

    PEM                                             OpenSsl
      new PemReader(textReader).ReadObject()        // type varies by label!
      new PemWriter(textWriter).WriteObject(obj)
      new Pkcs8Generator(privateKey [, Pkcs8Generator.PbeSha1_3DES])

    CERTIFICATES                                    X509 / Crypto.Operators
      new X509V3CertificateGenerator() + Set*/AddExtension
      .Generate(new Asn1SignatureFactory("SHA256WITHRSA", privateKey, random))
      new X509CertificateParser().ReadCertificate(bytes)   // DER or PEM
      cert.CheckValidity() ; cert.Verify(publicKey)

    PKCS#12                                         Pkcs
      new Pkcs12StoreBuilder().Build()
      .SetKeyEntry(alias, new AsymmetricKeyEntry(key), certEntryChain)
      .Save(stream, password, random) / .Load(stream, password)

    PATH VALIDATION                                 Pkix
      new PkixBuilderParameters(trustAnchors, targetSelector)
      + AddStoreCert / AddStoreCrl / Date / IsRevocationEnabled
      new PkixCertPathBuilder().Build(params).CertPath

    CMS                                             Cms
      new CmsSignedDataGenerator() + AddSigner + AddCertificates
      .Generate(new CmsProcessableByteArray(data), encapsulate)
      new CmsEnvelopedDataGenerator() + AddKeyTransRecipient
      .Generate(content, CmsEnvelopedGenerator.Aes256Cbc)
      recipient.GetContent(privateKey) ; signer.Verify(cert)

    OPENPGP                                         Bcpg / Bcpg.OpenPgp
      PgpUtilities.GetDecoderStream(stream)         // strips armor
      new PgpObjectFactory(stream).NextPgpObject()
      new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, random)
      new PgpLiteralDataGenerator().Open(out, Utf8, name, length, time)
      new ArmoredOutputStream(stream) / new ArmoredInputStream(stream)

    TLS                                             Tls / Tls.Crypto.Impl.BC
      class C : DefaultTlsClient { C() : base(new BcTlsCrypto()) {} ... }
      new TlsClientProtocol(stream).Connect(client) -> protocol.Stream
      VALIDATE in TlsAuthentication.NotifyServerCertificate

    ENCODERS                                        Utilities.Encoders
      Hex.ToHexString(bytes) / Hex.Decode(string)
      Base64.ToBase64String(bytes) / Base64.Decode(string)

    CONFIG                                          Utilities
      Properties.SetThreadInt32(Properties.Asn1MaxDepth, 64)
      keys keep their "Org.BouncyCastle.*" spelling on purpose

    EXCEPTIONS
      InvalidCipherTextException  auth/padding failure  (Crypto)
      SecurityUtilityException    unknown algorithm     (Security)
      Asn1Exception               bad encoding          (Asn1)
      CmsException / PgpException / TlsFatalAlert / OcspException /
      TspException / PkcsException / PkixCertPath*Exception
