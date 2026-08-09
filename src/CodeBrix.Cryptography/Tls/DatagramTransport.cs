using System;

namespace CodeBrix.Cryptography.Tls; //was previously: Org.BouncyCastle.Tls;

/// <summary>Base interface for an object sending and receiving DTLS data.</summary>
public interface DatagramTransport
    : DatagramReceiver, DatagramSender, TlsCloseable
{
}
