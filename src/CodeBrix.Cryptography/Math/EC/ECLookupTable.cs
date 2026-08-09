using System;

namespace CodeBrix.Cryptography.Math.EC; //was previously: Org.BouncyCastle.Math.EC;

public interface ECLookupTable
{
    int Size { get; }
    ECPoint Lookup(int index);
    ECPoint LookupVar(int index);
}
