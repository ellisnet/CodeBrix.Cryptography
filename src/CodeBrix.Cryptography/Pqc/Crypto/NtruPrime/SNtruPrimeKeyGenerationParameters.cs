using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Pqc.Crypto.NtruPrime; //was previously: Org.BouncyCastle.Pqc.Crypto.NtruPrime;

public class SNtruPrimeKeyGenerationParameters : KeyGenerationParameters
{
    private SNtruPrimeParameters _primeParameters;

    public SNtruPrimeKeyGenerationParameters(SecureRandom random, SNtruPrimeParameters ntruPrimeParameters) : base(random,256)
    {
        this._primeParameters = ntruPrimeParameters;
    }

    public SNtruPrimeParameters Parameters => _primeParameters;

}
