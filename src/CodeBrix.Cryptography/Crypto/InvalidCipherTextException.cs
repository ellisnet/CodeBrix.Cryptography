using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Crypto; //was previously: Org.BouncyCastle.Crypto;

/// <summary>This exception is thrown whenever we find something we don't expect in a message.</summary>
[Serializable]
public class InvalidCipherTextException
    : CryptoException
{
    public InvalidCipherTextException()
        : base()
    {
    }

    public InvalidCipherTextException(string message)
        : base(message)
    {
    }

    public InvalidCipherTextException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected InvalidCipherTextException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
