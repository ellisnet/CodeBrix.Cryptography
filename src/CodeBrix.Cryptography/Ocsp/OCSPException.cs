using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Ocsp; //was previously: Org.BouncyCastle.Ocsp;

[Serializable]
public class OcspException
    : Exception
{
    public OcspException()
        : base()
    {
    }

    public OcspException(string message)
        : base(message)
    {
    }

    public OcspException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected OcspException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
