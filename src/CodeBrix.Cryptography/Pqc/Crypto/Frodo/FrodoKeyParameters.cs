using CodeBrix.Cryptography.Crypto;

namespace CodeBrix.Cryptography.Pqc.Crypto.Frodo; //was previously: Org.BouncyCastle.Pqc.Crypto.Frodo;

public abstract class FrodoKeyParameters
    : AsymmetricKeyParameter
{
    private readonly FrodoParameters m_parameters;

    internal FrodoKeyParameters(bool isPrivate, FrodoParameters parameters)
        : base(isPrivate)
    {
        m_parameters = parameters;
    }

    public FrodoParameters Parameters => m_parameters;
}
