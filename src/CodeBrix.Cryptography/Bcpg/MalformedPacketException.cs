using System;
using System.IO;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Bcpg; //was previously: Org.BouncyCastle.Bcpg;

[Serializable]
public class MalformedPacketException
    : IOException
{
    public MalformedPacketException()
        : base()
    {
    }

    public MalformedPacketException(string message)
        : base(message)
    {
    }

    public MalformedPacketException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected MalformedPacketException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
