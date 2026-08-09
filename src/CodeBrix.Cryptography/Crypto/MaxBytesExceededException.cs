using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Crypto; //was previously: Org.BouncyCastle.Crypto;

/// <summary>This exception is thrown whenever a cipher requires a change of key, IV or similar after x amount of
/// bytes enciphered.
/// </summary>
[Serializable]
public class MaxBytesExceededException
    : CryptoException
{
    public MaxBytesExceededException()
        : base()
    {
    }

    public MaxBytesExceededException(string message)
        : base(message)
    {
    }

    public MaxBytesExceededException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected MaxBytesExceededException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
