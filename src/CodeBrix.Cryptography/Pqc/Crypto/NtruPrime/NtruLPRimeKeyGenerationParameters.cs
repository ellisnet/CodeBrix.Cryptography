using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Pqc.Crypto.NtruPrime; //was previously: Org.BouncyCastle.Pqc.Crypto.NtruPrime;

public class NtruLPRimeKeyGenerationParameters : KeyGenerationParameters
{
    private NtruLPRimeParameters _primeParameters;

    public NtruLPRimeKeyGenerationParameters(SecureRandom random, NtruLPRimeParameters ntruPrimeParameters) : base(random,256)
    {
        this._primeParameters = ntruPrimeParameters;
    }

    public NtruLPRimeParameters Parameters => _primeParameters;

}
