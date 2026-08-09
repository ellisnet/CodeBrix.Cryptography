using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Pqc.Crypto.Frodo; //was previously: Org.BouncyCastle.Pqc.Crypto.Frodo;

public class FrodoKeyGenerationParameters
    : KeyGenerationParameters
{
    private readonly FrodoParameters m_parameters;

    public FrodoKeyGenerationParameters(SecureRandom random, FrodoParameters frodoParameters)
        : base(random, 256)
    {
        m_parameters = frodoParameters;
    }

    public FrodoParameters Parameters => m_parameters;
}
