using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Pqc.Crypto.Falcon; //was previously: Org.BouncyCastle.Pqc.Crypto.Falcon;

public class FalconKeyGenerationParameters
    : KeyGenerationParameters
{
    private FalconParameters parameters;

    public FalconKeyGenerationParameters(SecureRandom random, FalconParameters parameters)
        : base(random, 320)
    {
        this.parameters = parameters;
    }

    public FalconParameters Parameters
    {
        get { return this.parameters; }
    }
}
