using CodeBrix.Cryptography.Crypto;

namespace CodeBrix.Cryptography.Pqc.Crypto.Saber; //was previously: Org.BouncyCastle.Pqc.Crypto.Saber;

public abstract class SaberKeyParameters
    : AsymmetricKeyParameter
{
    private readonly SaberParameters m_parameters;

    internal SaberKeyParameters(bool isPrivate, SaberParameters parameters)
        : base(isPrivate)
    {
        m_parameters = parameters;
    }

    public SaberParameters Parameters => m_parameters;
}
