using CodeBrix.Cryptography.Asn1.X509;

namespace CodeBrix.Cryptography.Asn1.Smime; //was previously: Org.BouncyCastle.Asn1.Smime;

public class SmimeCapabilitiesAttribute
    : AttributeX509
{
    public SmimeCapabilitiesAttribute(SmimeCapabilityVector capabilities)
        : base(SmimeAttributes.SmimeCapabilities,
            DerSet.FromElement(DerSequence.FromVector(capabilities.ToAsn1EncodableVector())))
    {
    }
}
