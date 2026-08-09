using System;
using CodeBrix.Cryptography.Crypto.Prng.Drbg;

namespace CodeBrix.Cryptography.Crypto.Prng; //was previously: Org.BouncyCastle.Crypto.Prng;

internal interface IDrbgProvider
{
    ISP80090Drbg Get(IEntropySource entropySource);
}
