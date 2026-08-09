using CodeBrix.Cryptography.Asn1.Crmf;
using CodeBrix.Cryptography.Asn1.X509;

namespace CodeBrix.Cryptography.Crmf; //was previously: Org.BouncyCastle.Crmf;

/// <summary>Parser for EncryptedValue structures.</summary>
public class EncryptedValueParser
{
    private readonly EncryptedValue m_value;
    private readonly IEncryptedValuePadder m_padder;

    /**
     * Basic constructor - create a parser to read the passed in value.
     *
     * @param value the value to be parsed.
     */
    public EncryptedValueParser(EncryptedValue value)
        : this(value, null)
    {
    }

    /**
     * Create a parser to read the passed in value, assuming the padder was
     * applied to the data prior to encryption.
     *
     * @param value  the value to be parsed.
     * @param padder the padder to be used to remove padding from the decrypted value..
     */
    public EncryptedValueParser(EncryptedValue value, IEncryptedValuePadder padder)
    {
        m_value = value;
        m_padder = padder;
    }

    public virtual AlgorithmIdentifier IntendedAlg => m_value.IntendedAlg;

    // TODO[crmf]

    private byte[] UnpadData(byte[] data) => m_padder?.GetUnpaddedData(data) ?? data;
}
