using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Math;
using CodeBrix.Cryptography.Math.EC;

namespace CodeBrix.Cryptography.Bcpg; //was previously: Org.BouncyCastle.Bcpg;

/// <remarks>Base class for an ECDSA Public Key.</remarks>
public class ECDsaPublicBcpgKey
    : ECPublicBcpgKey
{
    /// <param name="bcpgIn">The stream to read the packet from.</param>
    protected internal ECDsaPublicBcpgKey(BcpgInputStream bcpgIn)
        : base(bcpgIn)
    {
    }

    public ECDsaPublicBcpgKey(DerObjectIdentifier oid, ECPoint point)
        : base(oid, point)
    {
    }

    public ECDsaPublicBcpgKey(DerObjectIdentifier oid, BigInteger encodedPoint)
        : base(oid, encodedPoint)
    {
    }
}
