using System;
using System.IO;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Utilities.IO; //was previously: Org.BouncyCastle.Utilities.IO;

[Serializable]
public class StreamOverflowException
    : IOException
{
    public StreamOverflowException()
        : base()
    {
    }

    public StreamOverflowException(string message)
        : base(message)
    {
    }

    public StreamOverflowException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected StreamOverflowException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
