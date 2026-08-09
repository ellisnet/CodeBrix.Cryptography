using System;

namespace CodeBrix.Cryptography.Pqc.Crypto.Falcon; //was previously: Org.BouncyCastle.Pqc.Crypto.Falcon;

internal struct FalconFPR
{
    internal double v;

    internal FalconFPR(double v)
    {
        this.v = v;
    }
}
