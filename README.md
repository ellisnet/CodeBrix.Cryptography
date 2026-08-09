# CodeBrix.Cryptography

A fully managed, cross-platform, general-purpose cryptography library for .NET 10 (and higher).
CodeBrix.Cryptography has no dependencies other than .NET, and is provided as a .NET 10 library and associated `CodeBrix.Cryptography.MitLicenseForever` NuGet package.

CodeBrix.Cryptography supports applications and assemblies that target Microsoft .NET version 10.0 and later.
Microsoft .NET version 10.0 is a Long-Term Supported (LTS) version of .NET, and was released on Nov 11, 2025; and will be actively supported by Microsoft until Nov 14, 2028.
Please update your C#/.NET code and projects to the latest LTS version of Microsoft .NET.

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
> This carries over from upstream BouncyCastle.NET, which states the same about its NIST
> Post-Quantum Cryptography Standardization implementations. Treat their APIs and encodings as
> unstable across releases, and do not depend on them for long-lived data.

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

## Migrating from BouncyCastle.Cryptography

1. Replace the `BouncyCastle.Cryptography` package reference with `CodeBrix.Cryptography.MitLicenseForever`.
2. Replace `Org.BouncyCastle` with `CodeBrix.Cryptography` in your `using` directives and any fully-qualified type names.

Type names, member names and signatures are unchanged. The runtime configuration keys read from environment variables (`Org.BouncyCastle.Asn1.MaxDepth` and friends) also keep their original spelling, so existing configuration continues to apply.

## License

The project is licensed under the MIT License. see: https://en.wikipedia.org/wiki/MIT_License

CodeBrix.Cryptography is a fork of BouncyCastle.NET, which is Copyright (c) 2000-2026 The Legion of the Bouncy Castle Inc. and is also MIT licensed. See `THIRD-PARTY-NOTICES.txt` for the full attribution of BouncyCastle.NET and of the JZlib, Apache Ant BZip2, Falcon and Blake2Fast components it incorporates.
