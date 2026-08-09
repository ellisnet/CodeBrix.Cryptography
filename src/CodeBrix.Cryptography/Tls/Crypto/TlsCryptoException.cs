using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Tls.Crypto; //was previously: Org.BouncyCastle.Tls.Crypto;

/// <summary>Basic exception class for crypto services to pass back a cause.</summary>
[Serializable]
public class TlsCryptoException
    : TlsException
{
    public TlsCryptoException()
        : base()
    {
    }

    public TlsCryptoException(string message)
        : base(message)
    {
    }

    public TlsCryptoException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected TlsCryptoException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
