using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Pqc.Crypto.Lms; //was previously: Org.BouncyCastle.Pqc.Crypto.Lms;

// TODO[api] Make internal
[Serializable]
public class LmsException
    : Exception
{
    public LmsException()
        : base()
    {
    }

    public LmsException(string message)
        : base(message)
    {
    }

    public LmsException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected LmsException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
