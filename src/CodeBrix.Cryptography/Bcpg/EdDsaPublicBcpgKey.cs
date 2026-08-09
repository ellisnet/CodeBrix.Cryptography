using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Math;
using CodeBrix.Cryptography.Math.EC;

namespace CodeBrix.Cryptography.Bcpg; //was previously: Org.BouncyCastle.Bcpg;

public sealed class EdDsaPublicBcpgKey
    : ECPublicBcpgKey
{
    internal EdDsaPublicBcpgKey(BcpgInputStream bcpgIn)
        : base(bcpgIn)
    {
    }

    public EdDsaPublicBcpgKey(DerObjectIdentifier oid, ECPoint point)
        : base(oid, point)
    {
    }

    public EdDsaPublicBcpgKey(DerObjectIdentifier oid, BigInteger encodedPoint)
        : base(oid, encodedPoint)
    {
    }
}
