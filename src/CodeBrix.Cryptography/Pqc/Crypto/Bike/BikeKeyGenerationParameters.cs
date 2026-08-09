using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Pqc.Crypto.Bike; //was previously: Org.BouncyCastle.Pqc.Crypto.Bike;

public sealed class BikeKeyGenerationParameters
    : KeyGenerationParameters
{
    private readonly BikeParameters m_parameters;

    public BikeKeyGenerationParameters(SecureRandom random, BikeParameters parameters)
        : base(random, 256)
    {
        m_parameters = parameters;
    }

    public BikeParameters Parameters => m_parameters;
}
