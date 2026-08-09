using System;

namespace CodeBrix.Cryptography.Math.EC.Multiplier; //was previously: Org.BouncyCastle.Math.EC.Multiplier;

public interface IPreCompCallback
{
    PreCompInfo Precompute(PreCompInfo existing);
}
