using System;

namespace CodeBrix.Cryptography.Crypto.Engines; //was previously: Org.BouncyCastle.Crypto.Engines;

public class AriaWrapPadEngine
    : Rfc5649WrapEngine
{
    public AriaWrapPadEngine()
        : base(new AriaEngine())
    {
    }
}
