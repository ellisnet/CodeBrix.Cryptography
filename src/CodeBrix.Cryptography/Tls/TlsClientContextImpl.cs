using System;
using CodeBrix.Cryptography.Tls.Crypto;

namespace CodeBrix.Cryptography.Tls; //was previously: Org.BouncyCastle.Tls;

internal class TlsClientContextImpl
    : AbstractTlsContext, TlsClientContext
{
    internal TlsClientContextImpl(TlsCrypto crypto)
        : base(crypto, ConnectionEnd.client)
    {
    }

    public override bool IsServer
    {
        get { return false; }
    }
}
