using System;
using CodeBrix.Cryptography.Crypto;

namespace CodeBrix.Cryptography.Pqc.Crypto.Falcon; //was previously: Org.BouncyCastle.Pqc.Crypto.Falcon;

public abstract class FalconKeyParameters
    : AsymmetricKeyParameter
{
    private readonly FalconParameters m_parameters;

    internal FalconKeyParameters(bool isPrivate, FalconParameters parameters)
        : base(isPrivate)
    {
        m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
    }

    public FalconParameters Parameters => m_parameters;
}
