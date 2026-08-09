using System;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Pqc.Crypto.Crystals.Dilithium; //was previously: Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

[Obsolete("Use ML-DSA instead")]
public class DilithiumKeyGenerationParameters
    : KeyGenerationParameters
{
    private DilithiumParameters parameters;

    public DilithiumKeyGenerationParameters(SecureRandom random, DilithiumParameters parameters) : base(random, 255)
    {
        this.parameters = parameters;
    }

    public DilithiumParameters Parameters => parameters;
}
