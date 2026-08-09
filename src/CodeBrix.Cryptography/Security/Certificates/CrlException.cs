using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Security.Certificates; //was previously: Org.BouncyCastle.Security.Certificates;

[Serializable]
public class CrlException
    : GeneralSecurityException
{
    public CrlException()
        : base()
    {
    }

    public CrlException(string message)
        : base(message)
    {
    }

    public CrlException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected CrlException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
