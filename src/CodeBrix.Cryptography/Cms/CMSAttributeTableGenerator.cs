using System.Collections.Generic;
using CodeBrix.Cryptography.Asn1.Cms;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

/// <remarks>
/// The 'Signature' parameter is only available when generating unsigned attributes.
/// </remarks>
public enum CmsAttributeTableParameter
{
    ContentType, Digest, Signature, DigestAlgorithmIdentifier, SignatureAlgorithmIdentifier, MacAlgorithmIdentifier,
}

public interface CmsAttributeTableGenerator
{
    AttributeTable GetAttributes(IDictionary<CmsAttributeTableParameter, object> parameters);
}
