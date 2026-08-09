using System;

namespace CodeBrix.Cryptography.Math.Field; //was previously: Org.BouncyCastle.Math.Field;

public interface IExtensionField
    : IFiniteField
{
    IFiniteField Subfield { get; }

    int Degree { get; }
}
