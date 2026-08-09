using System;
using System.IO;

namespace CodeBrix.Cryptography.Tls; //was previously: Org.BouncyCastle.Tls;

internal interface DtlsHandshakeRetransmit
{
    /// <exception cref="IOException"/>
    void ReceivedHandshakeRecord(int epoch, byte[] buf, int off, int len);
}
