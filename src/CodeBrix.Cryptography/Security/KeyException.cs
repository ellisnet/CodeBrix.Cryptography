using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Security; //was previously: Org.BouncyCastle.Security;

[Serializable]
public class KeyException
    : GeneralSecurityException
{
    public KeyException()
        : base()
    {
    }

    public KeyException(string message)
        : base(message)
    {
    }

    public KeyException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected KeyException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
