using CodeBrix.Cryptography.Crypto;

namespace CodeBrix.Cryptography.Pqc.Crypto.NtruPrime; //was previously: Org.BouncyCastle.Pqc.Crypto.NtruPrime;

public abstract class NtruLPRimeKeyParameters
    : AsymmetricKeyParameter
{
    private readonly NtruLPRimeParameters m_primeParameters;

    internal NtruLPRimeKeyParameters(bool isPrivate, NtruLPRimeParameters primeParameters)
        : base(isPrivate)
    {
        m_primeParameters = primeParameters;
    }

    public NtruLPRimeParameters Parameters => m_primeParameters;
}
