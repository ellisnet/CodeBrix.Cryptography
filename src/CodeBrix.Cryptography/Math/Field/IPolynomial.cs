using System;

namespace CodeBrix.Cryptography.Math.Field; //was previously: Org.BouncyCastle.Math.Field;

public interface IPolynomial
{
    int Degree { get; }

    //BigInteger[] GetCoefficients();

    int[] GetExponentsPresent();

    //Term[] GetNonZeroTerms();
}
