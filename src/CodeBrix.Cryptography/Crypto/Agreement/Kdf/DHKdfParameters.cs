using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Utilities;

namespace CodeBrix.Cryptography.Crypto.Agreement.Kdf; //was previously: Org.BouncyCastle.Crypto.Agreement.Kdf;

public class DHKdfParameters
    : IDerivationParameters
{
    private readonly DerObjectIdentifier m_algorithm;
    private readonly int m_keySize;
    private readonly byte[] m_z;
    private readonly byte[] m_extraInfo;

    public DHKdfParameters(DerObjectIdentifier algorithm, int keySize, byte[] z)
        : this(algorithm, keySize, z, null)
    {
    }

    public DHKdfParameters(DerObjectIdentifier algorithm, int keySize, byte[] z, byte[] extraInfo)
    {
        m_algorithm = algorithm;
        m_keySize = keySize;
        m_z = Arrays.CopyBuffer(z);
        m_extraInfo = Arrays.Clone(extraInfo);
    }

    public DerObjectIdentifier Algorithm => m_algorithm;

    internal byte[] ExtraInfo => m_extraInfo;

    public byte[] GetZ() => Arrays.CopyBuffer(m_z);

    public byte[] GetExtraInfo() => Arrays.Clone(m_extraInfo);

    public int KeySize => m_keySize;

    internal byte[] Z => m_z;
}
