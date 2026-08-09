using System;

namespace CodeBrix.Cryptography.Math.EC.Endo; //was previously: Org.BouncyCastle.Math.EC.Endo;

public interface ECEndomorphism
{
    ECPointMap PointMap { get; }

    bool HasEfficientPointMap { get; }
}
