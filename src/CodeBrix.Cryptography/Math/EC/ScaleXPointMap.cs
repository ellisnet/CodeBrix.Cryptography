using System;

namespace CodeBrix.Cryptography.Math.EC; //was previously: Org.BouncyCastle.Math.EC;

public class ScaleXPointMap
    : ECPointMap
{
    protected readonly ECFieldElement scale;

    public ScaleXPointMap(ECFieldElement scale)
    {
        this.scale = scale;
    }

    public virtual ECPoint Map(ECPoint p)
    {
        return p.ScaleX(scale);
    }
}
