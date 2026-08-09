using System;

namespace CodeBrix.Cryptography.Math.Field; //was previously: Org.BouncyCastle.Math.Field;

public interface IFiniteField
{
    BigInteger Characteristic { get; }

    int Dimension { get; }
}
