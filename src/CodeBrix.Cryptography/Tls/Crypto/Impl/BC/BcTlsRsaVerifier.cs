using System;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Digests;
using CodeBrix.Cryptography.Crypto.Encodings;
using CodeBrix.Cryptography.Crypto.Engines;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Crypto.Signers;

namespace CodeBrix.Cryptography.Tls.Crypto.Impl.BC; //was previously: Org.BouncyCastle.Tls.Crypto.Impl.BC;

/// <summary>Operator supporting the verification of RSASSA-PKCS1-v1_5 signatures using the BC light-weight API.
/// </summary>
public class BcTlsRsaVerifier
    : BcTlsVerifier
{
    public BcTlsRsaVerifier(BcTlsCrypto crypto, RsaKeyParameters publicKey)
        : base(crypto, publicKey)
    {
    }

    public override bool VerifyRawSignature(DigitallySigned digitallySigned, byte[] hash)
    {
        IDigest nullDigest = new NullDigest();

        SignatureAndHashAlgorithm algorithm = digitallySigned.Algorithm;
        ISigner signer;
        if (algorithm != null)
        {
            if (algorithm.Signature != SignatureAlgorithm.rsa)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            /*
             * RFC 5246 4.7. In RSA signing, the opaque vector contains the signature generated
             * using the RSASSA-PKCS1-v1_5 signature scheme defined in [PKCS1].
             */
            signer = new RsaDigestSigner(nullDigest, TlsUtilities.GetOidForHashAlgorithm(algorithm.Hash));
        }
        else
        {
            /*
             * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
             * that did not include a DigestInfo encoding.
             */
            signer = new GenericSigner(new Pkcs1Encoding(new RsaBlindedEngine()), nullDigest);
        }
        signer.Init(false, m_publicKey);
        signer.BlockUpdate(hash, 0, hash.Length);
        return signer.VerifySignature(digitallySigned.Signature);
    }
}
