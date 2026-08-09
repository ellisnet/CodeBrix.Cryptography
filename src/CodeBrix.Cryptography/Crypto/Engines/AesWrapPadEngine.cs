using System;

namespace CodeBrix.Cryptography.Crypto.Engines; //was previously: Org.BouncyCastle.Crypto.Engines;

public class AesWrapPadEngine
    : Rfc5649WrapEngine
{
    public AesWrapPadEngine()
        : base(AesUtilities.CreateEngine())
    {
    }
}
