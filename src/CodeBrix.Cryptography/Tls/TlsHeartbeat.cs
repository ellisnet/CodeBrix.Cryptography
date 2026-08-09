using System;

namespace CodeBrix.Cryptography.Tls; //was previously: Org.BouncyCastle.Tls;

public interface TlsHeartbeat
{
    byte[] GeneratePayload();

    int IdleMillis { get; }

    int TimeoutMillis { get; }
}
