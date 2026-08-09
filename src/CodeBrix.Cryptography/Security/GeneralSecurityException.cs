using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Security; //was previously: Org.BouncyCastle.Security;

[Serializable]
public class GeneralSecurityException
    : Exception
{
    public GeneralSecurityException()
        : base()
    {
    }

    public GeneralSecurityException(string message)
        : base(message)
    {
    }

    public GeneralSecurityException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected GeneralSecurityException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
