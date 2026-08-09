using CodeBrix.Cryptography.Asn1.Pkcs;

namespace CodeBrix.Cryptography.Asn1.Cms; //was previously: Org.BouncyCastle.Asn1.Cms;

// TODO[api] Make static
public abstract class CmsAttributes
{
    public static readonly DerObjectIdentifier ContentType = PkcsObjectIdentifiers.Pkcs9AtContentType;
    public static readonly DerObjectIdentifier MessageDigest = PkcsObjectIdentifiers.Pkcs9AtMessageDigest;
    public static readonly DerObjectIdentifier SigningTime = PkcsObjectIdentifiers.Pkcs9AtSigningTime;
    public static readonly DerObjectIdentifier CounterSignature = PkcsObjectIdentifiers.Pkcs9AtCounterSignature;
    public static readonly DerObjectIdentifier ContentHint = PkcsObjectIdentifiers.IdAAContentHint;
    public static readonly DerObjectIdentifier CmsAlgorithmProtect = PkcsObjectIdentifiers.id_aa_cmsAlgorithmProtect;
}
