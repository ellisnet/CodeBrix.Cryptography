using System;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Pqc.Crypto.SphincsPlus; //was previously: Org.BouncyCastle.Pqc.Crypto.SphincsPlus;

[Obsolete("Use SLH-DSA instead")]
public sealed class SphincsPlusKeyGenerationParameters
    : KeyGenerationParameters
{
    private readonly SphincsPlusParameters m_parameters;

    public SphincsPlusKeyGenerationParameters(SecureRandom random, SphincsPlusParameters parameters)
        : base(random, 256)
    {
        m_parameters = parameters;
    }

    public SphincsPlusParameters Parameters => m_parameters;
}
