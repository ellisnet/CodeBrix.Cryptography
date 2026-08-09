using System;
using CodeBrix.Cryptography.Crypto.Kems.MLKem;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities;

namespace CodeBrix.Cryptography.Crypto.Kems; //was previously: Org.BouncyCastle.Crypto.Kems;

public sealed class MLKemDecapsulator
    : IKemDecapsulator
{
    private readonly MLKemParameters m_parameters;

    private MLKemPrivateKeyParameters m_privateKey;
    private MLKemEngine m_engine;

    public MLKemDecapsulator(MLKemParameters parameters)
    {
        m_parameters = parameters;
    }

    public void Init(ICipherParameters parameters)
    {
        parameters = ParameterUtilities.IgnoreRandom(parameters);

        if (!(parameters is MLKemPrivateKeyParameters privateKey))
            throw new ArgumentException($"{nameof(MLKemDecapsulator)} expects {nameof(MLKemPrivateKeyParameters)}");

        m_privateKey = privateKey;
        m_engine = GetEngine(m_privateKey.Parameters);
    }

    public int EncapsulationLength => m_engine.CipherTextBytes;

    public int SecretLength => MLKemEngine.SharedSecretBytes;

    public void Decapsulate(byte[] encBuf, int encOff, int encLen, byte[] secBuf, int secOff, int secLen)
    {
        Arrays.ValidateSegment(encBuf, encOff, encLen);
        Arrays.ValidateSegment(secBuf, secOff, secLen);

        Decapsulate(encBuf.AsSpan(encOff, encLen), secBuf.AsSpan(secOff, secLen));
    }

    public void Decapsulate(ReadOnlySpan<byte> encapsulation, Span<byte> secret)
    {
        if (EncapsulationLength != encapsulation.Length)
            throw new ArgumentException(nameof(encapsulation));
        if (SecretLength != secret.Length)
            throw new ArgumentException(nameof(secret));

        m_engine.KemDecrypt(m_privateKey.Encoding.AsSpan(), encapsulation, secret);
    }

    private MLKemEngine GetEngine(MLKemParameters keyParameters)
    {
        var keyParameterSet = keyParameters.ParameterSet;

        if (keyParameterSet != m_parameters.ParameterSet)
            throw new ArgumentException("Mismatching key parameter set", nameof(keyParameters));

        return keyParameterSet.Engine;
    }
}
