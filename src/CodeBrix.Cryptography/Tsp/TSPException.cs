using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Tsp; //was previously: Org.BouncyCastle.Tsp;

[Serializable]
public class TspException
    : Exception
{
    public TspException()
        : base()
    {
    }

    public TspException(string message)
        : base(message)
    {
    }

    public TspException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected TspException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
