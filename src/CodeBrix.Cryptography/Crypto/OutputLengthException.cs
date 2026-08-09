using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Crypto; //was previously: Org.BouncyCastle.Crypto;

[Serializable]
public class OutputLengthException
    : DataLengthException
{
    public OutputLengthException()
        : base()
    {
    }

    public OutputLengthException(string message)
        : base(message)
    {
    }

    public OutputLengthException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected OutputLengthException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
