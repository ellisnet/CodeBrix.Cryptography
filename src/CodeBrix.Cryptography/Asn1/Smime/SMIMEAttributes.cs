using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Pkcs;

namespace CodeBrix.Cryptography.Asn1.Smime; //was previously: Org.BouncyCastle.Asn1.Smime;

public abstract class SmimeAttributes
{
    public static readonly DerObjectIdentifier SmimeCapabilities = PkcsObjectIdentifiers.Pkcs9AtSmimeCapabilities;
    public static readonly DerObjectIdentifier EncrypKeyPref = PkcsObjectIdentifiers.IdAAEncrypKeyPref;
}
