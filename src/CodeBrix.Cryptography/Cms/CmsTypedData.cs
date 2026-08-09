using CodeBrix.Cryptography.Asn1;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

public interface CmsTypedData
    : CmsProcessable
{
    DerObjectIdentifier ContentType { get; }
}
