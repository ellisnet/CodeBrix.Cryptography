using System;

namespace CodeBrix.Cryptography.Math.EC.Endo; //was previously: Org.BouncyCastle.Math.EC.Endo;

public interface GlvEndomorphism
    :   ECEndomorphism
{
    BigInteger[] DecomposeScalar(BigInteger k);
}
