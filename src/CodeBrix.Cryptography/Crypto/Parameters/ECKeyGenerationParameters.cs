using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Crypto.Parameters; //was previously: Org.BouncyCastle.Crypto.Parameters;

public class ECKeyGenerationParameters
    : KeyGenerationParameters
{
    private readonly ECDomainParameters m_domainParameters;

    public ECKeyGenerationParameters(ECDomainParameters domainParameters, SecureRandom random)
        : base(random, domainParameters.N.BitLength)
    {
        m_domainParameters = domainParameters;
    }

    public ECKeyGenerationParameters(DerObjectIdentifier publicKeyParamSet, SecureRandom random)
        : this(ECNamedDomainParameters.LookupOid(oid: publicKeyParamSet), random)
    {
    }

    public ECDomainParameters DomainParameters => m_domainParameters;

    public DerObjectIdentifier PublicKeyParamSet => (m_domainParameters as ECNamedDomainParameters)?.Name;
}
