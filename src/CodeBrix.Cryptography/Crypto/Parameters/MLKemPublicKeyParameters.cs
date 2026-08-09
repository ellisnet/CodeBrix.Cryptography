using System;
using CodeBrix.Cryptography.Crypto.Kems.MLKem;
using CodeBrix.Cryptography.Utilities;

namespace CodeBrix.Cryptography.Crypto.Parameters; //was previously: Org.BouncyCastle.Crypto.Parameters;

/// <summary>
/// An ML-KEM public (encapsulation) key, represented by the raw byte encoding defined in FIPS 203.
/// </summary>
/// <remarks>
/// Instances are immutable and can be used to perform key encapsulation. Create instances via
/// <see cref="FromEncoding(MLKemParameters, byte[])"/> or by generating a key pair; the constructor is
/// internal.
/// </remarks>
public sealed class MLKemPublicKeyParameters
    : MLKemKeyParameters
{
    /// <summary>
    /// Create an <see cref="MLKemPublicKeyParameters"/> from its raw FIPS 203 public key encoding.
    /// </summary>
    /// <param name="parameters">The ML-KEM algorithm parameters this key belongs to.</param>
    /// <param name="encoding">The raw public key bytes. Length must equal the parameter set's
    /// <c>PublicKeyBytes</c>.</param>
    /// <returns>A new <see cref="MLKemPublicKeyParameters"/> wrapping a defensive copy of
    /// <paramref name="encoding"/>.</returns>
    /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> or
    /// <paramref name="encoding"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">If <paramref name="encoding"/> has the wrong length or fails the
    /// FIPS 203 modulus check.</exception>
    public static MLKemPublicKeyParameters FromEncoding(MLKemParameters parameters, byte[] encoding)
    {
        if (parameters == null)
            throw new ArgumentNullException(nameof(parameters));
        if (encoding == null)
            throw new ArgumentNullException(nameof(encoding));

        var engine = parameters.ParameterSet.Engine;

        if (encoding.Length != engine.PublicKeyBytes)
            throw new ArgumentException("Invalid length", nameof(encoding));

        encoding = Arrays.InternalCopyBuffer(encoding);

        if (!engine.CheckEncapKeyModulus(encoding))
            throw new ArgumentException("Modulus check failed", nameof(encoding));

        return new MLKemPublicKeyParameters(parameters, encoding);
    }

    internal readonly byte[] m_encoding;

    internal MLKemPublicKeyParameters(MLKemParameters parameters, byte[] encoding)
        : base(isPrivate: false, parameters)
    {
        m_encoding = encoding ?? throw new ArgumentNullException(nameof(encoding));
    }

    internal byte[] Encoding => m_encoding;

    /// <summary>Returns a copy of the raw FIPS 203 public key encoding.</summary>
    public byte[] GetEncoded() => Arrays.InternalCopyBuffer(m_encoding);

    // NB: Don't remove - needed by commented-out test cases
    internal Tuple<byte[], byte[]> InternalEncapsulate(byte[] randBytes)
    {
        if (randBytes.Length != MLKemEngine.SymBytes)
            throw new ArgumentException("Invalid length", nameof(randBytes));

        var engine = Parameters.ParameterSet.Engine;

        byte[] enc = new byte[engine.CipherTextBytes];
        byte[] sec = new byte[MLKemEngine.SharedSecretBytes];
        engine.KemEncrypt(Encoding.AsSpan(), randBytes.AsSpan(), enc.AsSpan(), sec.AsSpan());
        return Tuple.Create(enc, sec);
    }
}
