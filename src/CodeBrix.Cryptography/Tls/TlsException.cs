using System;
using System.IO;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Tls; //was previously: Org.BouncyCastle.Tls;

[Serializable]
public class TlsException
    : IOException
{
    public TlsException()
        : base()
    {
    }

    public TlsException(string message)
        : base(message)
    {
    }

    public TlsException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected TlsException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
