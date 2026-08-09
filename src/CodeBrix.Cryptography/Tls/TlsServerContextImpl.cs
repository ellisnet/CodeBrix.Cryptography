using System;
using CodeBrix.Cryptography.Tls.Crypto;

namespace CodeBrix.Cryptography.Tls; //was previously: Org.BouncyCastle.Tls;

internal class TlsServerContextImpl
    : AbstractTlsContext, TlsServerContext
{
    internal TlsServerContextImpl(TlsCrypto crypto)
        : base(crypto, ConnectionEnd.server)
    {
    }

    public override bool IsServer
    {
        get { return true; }
    }
}
