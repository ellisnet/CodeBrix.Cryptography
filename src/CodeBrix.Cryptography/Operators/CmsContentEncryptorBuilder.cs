using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Operators;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Operators; //was previously: Org.BouncyCastle.Operators;

public class CmsContentEncryptorBuilder
{
    private readonly SecureRandom m_random;
    private readonly DerObjectIdentifier m_encryptionOid;
    private readonly int m_keySize;

    public CmsContentEncryptorBuilder(DerObjectIdentifier encryptionOID)
        : this(random: null, encryptionOID)
    {
    }

    public CmsContentEncryptorBuilder(DerObjectIdentifier encryptionOID, int keySize)
        : this(random: null, encryptionOID, keySize)
    {
    }

    public CmsContentEncryptorBuilder(SecureRandom random, DerObjectIdentifier encryptionOid)
        : this(random, encryptionOid, -1)
    {
    }

    public CmsContentEncryptorBuilder(SecureRandom random, DerObjectIdentifier encryptionOid, int keySize)
    {
        m_random = random;
        m_encryptionOid = encryptionOid;
        m_keySize = keySize;
    }

    public ICipherBuilderWithKey Build() => new Asn1CipherBuilderWithKey(m_encryptionOid, m_keySize, m_random);
}
