using System;

namespace CodeBrix.Cryptography.Math.Field; //was previously: Org.BouncyCastle.Math.Field;

public interface IPolynomialExtensionField
    : IExtensionField
{
    IPolynomial MinimalPolynomial { get; }
}
