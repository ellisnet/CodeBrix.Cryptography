using System;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Cms.Ecc;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Crypto.Generators;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Crypto.Utilities;

namespace CodeBrix.Cryptography.Crypto.Agreement.Kdf; //was previously: Org.BouncyCastle.Crypto.Agreement.Kdf;

/**
 * X9.63 based key derivation function for ECDH CMS.
 */
public sealed class ECDHKekGenerator
    : IDerivationFunction
{
    private readonly IDerivationFunction m_kdf;

    private DHKdfParameters m_parameters;

    public ECDHKekGenerator(IDigest digest)
    {
        m_kdf = new Kdf2BytesGenerator(digest);
    }

    public void Init(IDerivationParameters param)
    {
        m_parameters = (DHKdfParameters)param ?? throw new ArgumentNullException(nameof(param));
    }

    public IDigest Digest => m_kdf.Digest;

    public int GenerateBytes(byte[] outBytes, int outOff, int length)
    {
        Check.OutputLength(outBytes, outOff, length, "output buffer too short");

        return GenerateBytes(outBytes.AsSpan(outOff, length));
    }

    public int GenerateBytes(Span<byte> output)
    {
        InitKdf();
        return m_kdf.GenerateBytes(output);
    }

    private void InitKdf()
    {
        var keyInfo = new AlgorithmIdentifier(m_parameters.Algorithm, DerNull.Instance);
        var suppPubInfo = DerOctetString.WithContents(Pack.UInt32_To_BE((uint)m_parameters.KeySize));
        // TODO Should the optional DHKdfParameters.ExtraInfo be used for ECC_CMS_SharedInfo.entityUInfo?
        var eccCmsSharedInfo = new ECC_CMS_SharedInfo(keyInfo, suppPubInfo);
        byte[] iv = eccCmsSharedInfo.GetEncoded(Asn1Encodable.Der);
        m_kdf.Init(new KdfParameters(m_parameters.Z, iv));
    }
}
