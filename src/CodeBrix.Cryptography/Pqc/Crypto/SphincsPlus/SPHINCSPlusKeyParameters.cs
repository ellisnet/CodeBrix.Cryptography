using System;
using CodeBrix.Cryptography.Crypto;

namespace CodeBrix.Cryptography.Pqc.Crypto.SphincsPlus; //was previously: Org.BouncyCastle.Pqc.Crypto.SphincsPlus;

[Obsolete("Use SLH-DSA instead")]
public abstract class SphincsPlusKeyParameters
    : AsymmetricKeyParameter
{
    private readonly SphincsPlusParameters m_parameters;

    internal SphincsPlusKeyParameters(bool isPrivate, SphincsPlusParameters parameters)
        : base(isPrivate)
    {
        m_parameters = parameters;
    }

    public SphincsPlusParameters Parameters => m_parameters;
}
