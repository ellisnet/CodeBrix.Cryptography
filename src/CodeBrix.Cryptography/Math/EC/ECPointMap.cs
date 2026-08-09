using System;

namespace CodeBrix.Cryptography.Math.EC; //was previously: Org.BouncyCastle.Math.EC;

public interface ECPointMap
{
    ECPoint Map(ECPoint p);
}
