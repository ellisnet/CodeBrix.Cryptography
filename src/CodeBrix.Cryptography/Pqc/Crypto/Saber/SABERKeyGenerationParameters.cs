using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Pqc.Crypto.Saber; //was previously: Org.BouncyCastle.Pqc.Crypto.Saber;

public sealed class SaberKeyGenerationParameters
    : KeyGenerationParameters
{
    private SaberParameters parameters;

    public SaberKeyGenerationParameters(SecureRandom random, SaberParameters saberParameters)
        : base(random, 256)
    {
        this.parameters = saberParameters;
    }

    public SaberParameters Parameters => parameters;
}
