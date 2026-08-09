using CodeBrix.Cryptography.Crypto;

namespace CodeBrix.Cryptography.Pqc.Crypto.NtruPrime; //was previously: Org.BouncyCastle.Pqc.Crypto.NtruPrime;

public abstract class SNtruPrimeKeyParameters
    : AsymmetricKeyParameter
{
    private readonly SNtruPrimeParameters m_primeParameters;

    internal SNtruPrimeKeyParameters(bool isPrivate, SNtruPrimeParameters primeParameters)
        : base(isPrivate)
    {
        m_primeParameters = primeParameters;
    }

    public SNtruPrimeParameters Parameters => m_primeParameters;
}
