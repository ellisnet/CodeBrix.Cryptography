using System;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Crypto.Signers;
using CodeBrix.Cryptography.Utilities;

namespace CodeBrix.Cryptography.Tls.Crypto.Impl.BC; //was previously: Org.BouncyCastle.Tls.Crypto.Impl.BC;

public class BcTlsSM2Signer
    : BcTlsSigner
{
    private readonly byte[] m_identifier;

    [Obsolete("Will be removed")]
    public BcTlsSM2Signer(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey, byte[] identifier)
        : base(crypto, privateKey)
    {
        m_identifier = Arrays.Clone(identifier);
    }

    public BcTlsSM2Signer(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey, int signatureScheme)
        : base(crypto, privateKey)
    {
        if (SignatureScheme.sm2sig_sm3 != signatureScheme)
            throw new ArgumentException($"{SignatureScheme.GetText(signatureScheme)} is not SM2",
                nameof(signatureScheme));

        m_identifier = Strings.ToByteArray("TLSv1.3+GM+Cipher+Suite");
    }

    public override TlsStreamSigner GetStreamSigner(SignatureAndHashAlgorithm algorithm)
    {
        if (algorithm == null || SignatureScheme.From(algorithm) != SignatureScheme.sm2sig_sm3)
            throw new InvalidOperationException("Invalid algorithm: " + algorithm);

        ParametersWithRandom parametersWithRandom = new ParametersWithRandom(m_privateKey, m_crypto.SecureRandom);
        ParametersWithID parametersWithID = new ParametersWithID(parametersWithRandom, m_identifier);

        SM2Signer signer = new SM2Signer();
        signer.Init(true, parametersWithID);

        return new BcTlsStreamSigner(signer);
    }
}
