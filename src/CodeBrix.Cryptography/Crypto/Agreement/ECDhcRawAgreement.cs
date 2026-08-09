using System;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Crypto.Agreement; //was previously: Org.BouncyCastle.Crypto.Agreement;

public sealed class ECDhcRawAgreement
    : IRawAgreement
{
    private ECPrivateKeyParameters m_privateKey;

    public void Init(ICipherParameters parameters)
    {
        var kParam = ParameterUtilities.IgnoreRandom(parameters);

        if (!(kParam is ECPrivateKeyParameters ecPrivateKeyParameters))
            throw new ArgumentException($"{nameof(ECDhcRawAgreement)} expects {nameof(ECPrivateKeyParameters)}");

        m_privateKey = ecPrivateKeyParameters;
    }

    public int AgreementSize => m_privateKey.Parameters.Curve.FieldElementEncodingLength;

    public void CalculateAgreement(ICipherParameters publicKey, byte[] buf, int off)
    {
        CalculateAgreement(publicKey, buf.AsSpan(off));
    }

    public void CalculateAgreement(ICipherParameters publicKey, Span<byte> output)
    {
        ECDHCBasicAgreement.CalculateAgreementFieldElement(m_privateKey, (ECPublicKeyParameters)publicKey)
            .EncodeTo(output[..AgreementSize]);
    }
}
