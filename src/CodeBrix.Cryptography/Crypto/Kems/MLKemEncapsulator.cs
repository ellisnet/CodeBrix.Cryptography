using System;
using CodeBrix.Cryptography.Crypto.Kems.MLKem;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities;

namespace CodeBrix.Cryptography.Crypto.Kems; //was previously: Org.BouncyCastle.Crypto.Kems;

public sealed class MLKemEncapsulator
    : IKemEncapsulator
{
    private readonly MLKemParameters m_parameters;

    private MLKemPublicKeyParameters m_publicKey;
    private SecureRandom m_random;
    private MLKemEngine m_engine;

    public MLKemEncapsulator(MLKemParameters parameters)
    {
        m_parameters = parameters;
    }

    public void Init(ICipherParameters parameters)
    {
        parameters = ParameterUtilities.GetRandom(parameters, out var providedRandom);

        if (!(parameters is MLKemPublicKeyParameters publicKey))
            throw new ArgumentException($"{nameof(MLKemEncapsulator)} expects {nameof(MLKemPublicKeyParameters)}");

        m_publicKey = publicKey;
        m_random = CryptoServicesRegistrar.GetSecureRandom(providedRandom);
        m_engine = GetEngine(m_publicKey.Parameters);
    }

    public int EncapsulationLength => m_engine.CipherTextBytes;

    public int SecretLength => MLKemEngine.SharedSecretBytes;

    public void Encapsulate(byte[] encBuf, int encOff, int encLen, byte[] secBuf, int secOff, int secLen)
    {
        Arrays.ValidateSegment(encBuf, encOff, encLen);
        Arrays.ValidateSegment(secBuf, secOff, secLen);

        Encapsulate(encBuf.AsSpan(encOff, encLen), secBuf.AsSpan(secOff, secLen));
    }

    public void Encapsulate(Span<byte> encapsulation, Span<byte> secret)
    {
        if (EncapsulationLength != encapsulation.Length)
            throw new ArgumentException(nameof(encapsulation));
        if (SecretLength != secret.Length)
            throw new ArgumentException(nameof(secret));

        Span<byte> randBytes = stackalloc byte[MLKemEngine.SymBytes];
        m_random.NextBytes(randBytes);

        m_engine.KemEncrypt(m_publicKey.Encoding.AsSpan(), randBytes, encapsulation, secret);
    }

    private MLKemEngine GetEngine(MLKemParameters keyParameters)
    {
        var keyParameterSet = keyParameters.ParameterSet;

        if (keyParameterSet != m_parameters.ParameterSet)
            throw new ArgumentException("Mismatching key parameter set", nameof(keyParameters));

        return keyParameterSet.Engine;
    }
}
