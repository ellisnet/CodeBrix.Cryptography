# CodeBrix.Cryptography

A fully managed, cross-platform, general-purpose cryptography library for .NET 10 (and higher).
CodeBrix.Cryptography has no dependencies other than .NET, and is provided as a .NET 10 library and associated `CodeBrix.Cryptography.MitLicenseForever` NuGet package.

CodeBrix.Cryptography supports applications and assemblies that target Microsoft .NET version 10.0 and later.
Microsoft .NET version 10.0 is a Long-Term Supported (LTS) version of .NET, and was released on Nov 11, 2025; and will be actively supported by Microsoft until Nov 14, 2028.
Please update your C#/.NET code and projects to the latest LTS version of Microsoft .NET.

## Installation

```
dotnet add package CodeBrix.Cryptography.MitLicenseForever
```

Note that the NuGet package ID and the namespace are different - there is no package named plain `CodeBrix.Cryptography`:

* NuGet package ID: `CodeBrix.Cryptography.MitLicenseForever`
* Assembly and primary namespace: `CodeBrix.Cryptography` - i.e. `using CodeBrix.Cryptography;`

The public API is spread across a family of sub-namespaces - `CodeBrix.Cryptography.Crypto` and its `Engines` / `Modes` / `Parameters` / `Generators` / `Operators` children, `.Asn1` and its per-specification children, `.Security`, `.Math`, `.X509`, `.Cms`, `.Pkcs`, `.Bcpg`, `.OpenSsl`, `.Tls` and others - so most code imports several of them; see the samples below.

XML documentation (IntelliSense) ships alongside the assembly.

The package has no NuGet dependencies of its own; it builds only against the .NET base class libraries.

### Runtime configuration

A number of hardening limits - ASN.1 parse depth, Argon2 and PBE cost ceilings, key-size ceilings and similar - are configurable at run time. Each is looked up first in the thread-local property table exposed by `CodeBrix.Cryptography.Utilities.Properties`, then in the process environment. The keys are spelled `Org.BouncyCastle.Asn1.MaxDepth`, `Org.BouncyCastle.Asn1.MaxLimit`, `Org.BouncyCastle.Argon2.MaxPasses`, `Org.BouncyCastle.Pbe.MaxIterationCount` and so on; `Properties` declares the full set as `public static readonly string` fields. Change them only if you need to raise or lower the defaults - the shipped values are the safe ones.

## CodeBrix.Cryptography supports:

* **ASN.1** — DER/BER/DL encoding and parsing, and the object-identifier and structure definitions for X.509, PKCS, CMS, CMP, CRMF, OCSP, TSP, X9.62, NIST, SEC, GNU, Rosstandart and many other specifications
* **Block and stream ciphers** — AES (with x86 AES-NI acceleration), ARIA, Blowfish, Camellia, CAST5/CAST6, ChaCha20, DES/Triple-DES, GOST 28147/Kuznyechik, IDEA, Noekeon, RC2/RC4/RC5/RC6, Rijndael, SEED, Serpent, Salsa20, SM4, Threefish, Twofish, XSalsa20 and more
* **Modes and padding** — CBC, CCM, CFB, CTS, EAX, ECB, GCM (with carry-less-multiply acceleration), GOFB, KCCM, KGCM, OCB, OFB, OpenPGP CFB, SIC/CTR, plus PKCS#7, ISO 7816-4, ISO 10126-2, TBC, X9.23 and zero-byte padding
* **Digests and XOFs** — SHA-1, the SHA-2 family, SHA-3, SHAKE, cSHAKE, KMAC, TupleHash, ParallelHash, BLAKE2b/BLAKE2s (x86-accelerated) and BLAKE3, Haraka, Keccak, MD2/MD4/MD5, RIPEMD, SM3, Skein, Whirlpool, GOST3411 and the DSTU/Ukrainian digests
* **MACs** — CBC-MAC, CMAC, GMAC, HMAC, KGMAC, Poly1305, SipHash, SkeinMac, DSTU7564Mac and more
* **Public-key cryptography** — RSA, DSA, Diffie-Hellman, ElGamal, ECDSA, ECDH/ECMQV, ECGOST, EdDSA (Ed25519 / Ed448), X25519 / X448, SM2, and the associated key generation, key agreement and signature schemes
* **Post-quantum cryptography** — ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+), LMS/HSS, XMSS/XMSS^MT, Falcon, BIKE, HQC, Classic McEliece, Frodo, NTRU / NTRU Prime, Picnic, SABER and SNOVA
* **Key derivation and password hashing** — Argon2, bcrypt, scrypt, HKDF, PBKDF1/PBKDF2, PKCS#12 KDF, Concatenation and X9.63 KDFs, and the TLS/SSL PRFs
* **TLS and DTLS** — a full TLS 1.0–1.3 and DTLS 1.0–1.2 client and server implementation, with pluggable crypto, PSK, SRP, raw public keys and certificate-type negotiation
* **OpenPGP** — key ring generation and management, encryption, signing, compression, ASCII armor and cleartext-signed messages
* **CMS / S-MIME, PKCS and certificates** — signed, enveloped, digested, encrypted and compressed CMS data, PKCS#1/#5/#7/#8/#10/#12, X.509 certificate, attribute-certificate and CRL generation, parsing and path validation (PKIX), OCSP, timestamping (TSP), CMP and CRMF
* **OpenSSL interoperability** — PEM reading and writing, including encrypted private keys


> **The post-quantum algorithms should be considered EXPERIMENTAL and subject to change or removal.**
> They implement the NIST Post-Quantum Cryptography Standardization candidates and standards, whose
> APIs and encodings should be treated as unstable across releases. Do not depend on them for
> long-lived data.

## Sample Code

### Authenticated encryption with AES-GCM

```csharp
using System;
using System.Text;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Engines;
using CodeBrix.Cryptography.Crypto.Modes;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Security;

var random = new SecureRandom();

byte[] key = new byte[32];          // AES-256
byte[] nonce = new byte[12];        // 96-bit nonce, never reused with the same key
random.NextBytes(key);
random.NextBytes(nonce);

byte[] plaintext = Encoding.UTF8.GetBytes("attack at dawn");
byte[] associatedData = Encoding.UTF8.GetBytes("message-id: 42");

// Encrypt: the 128-bit authentication tag is appended to the ciphertext.
var encryptor = new GcmBlockCipher(AesUtilities.CreateEngine());
encryptor.Init(forEncryption: true, new AeadParameters(new KeyParameter(key), 128, nonce, associatedData));

byte[] ciphertext = new byte[encryptor.GetOutputSize(plaintext.Length)];
int written = encryptor.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
encryptor.DoFinal(ciphertext, written);

// Decrypt: DoFinal throws InvalidCipherTextException if the tag does not verify.
var decryptor = new GcmBlockCipher(AesUtilities.CreateEngine());
decryptor.Init(forEncryption: false, new AeadParameters(new KeyParameter(key), 128, nonce, associatedData));

byte[] recovered = new byte[decryptor.GetOutputSize(ciphertext.Length)];
written = decryptor.ProcessBytes(ciphertext, 0, ciphertext.Length, recovered, 0);
written += decryptor.DoFinal(recovered, written);

Console.WriteLine(Encoding.UTF8.GetString(recovered, 0, written));   // attack at dawn
```

### Generating a self-signed X.509 certificate

```csharp
using System;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Generators;
using CodeBrix.Cryptography.Crypto.Operators;
using CodeBrix.Cryptography.Math;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.X509;

var random = new SecureRandom();

var keyPairGenerator = new RsaKeyPairGenerator();
keyPairGenerator.Init(new KeyGenerationParameters(random, 2048));
var keyPair = keyPairGenerator.GenerateKeyPair();

var name = new X509Name("CN=example.test, O=CodeBrix, C=US");

var certificateGenerator = new X509V3CertificateGenerator();
certificateGenerator.SetSerialNumber(BigInteger.ProbablePrime(120, random));
certificateGenerator.SetIssuerDN(name);
certificateGenerator.SetSubjectDN(name);
certificateGenerator.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
certificateGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
certificateGenerator.SetPublicKey(keyPair.Public);

var signatureFactory = new Asn1SignatureFactory("SHA256WITHRSA", keyPair.Private, random);
X509Certificate certificate = certificateGenerator.Generate(signatureFactory);

certificate.CheckValidity();
certificate.Verify(keyPair.Public);

Console.WriteLine(certificate.SubjectDN);          // CN=example.test,O=CodeBrix,C=US
Console.WriteLine(certificate.SigAlgName);         // SHA-256withRSA
```

## Documentation

The NuGet package includes `AGENT-README.txt`, a complete API reference and usage guide written for AI coding agents - point your agent at that file when it is writing code against this library.

Additional sample code and usage examples are available in the `CodeBrix.Cryptography.Tests` project, which is the richest set of worked examples available for this library:
https://github.com/ellisnet/CodeBrix.Cryptography/tree/main/tests/CodeBrix.Cryptography.Tests

## License

CodeBrix.Cryptography is licensed under the MIT License - see the
[LICENSE](https://github.com/ellisnet/CodeBrix.Cryptography/blob/main/LICENSE) file.

For licensing and provenance information about the open source code included in
this package, see [THIRD-PARTY-NOTICES.txt](https://github.com/ellisnet/CodeBrix.Cryptography/blob/main/THIRD-PARTY-NOTICES.txt).
