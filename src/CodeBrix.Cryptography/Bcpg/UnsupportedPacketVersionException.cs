using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Bcpg; //was previously: Org.BouncyCastle.Bcpg;

[Serializable]
public class UnsupportedPacketVersionException
    : Exception
{
    public UnsupportedPacketVersionException()
        : base()
    {
    }

    public UnsupportedPacketVersionException(string message)
        : base(message)
    {
    }

    public UnsupportedPacketVersionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected UnsupportedPacketVersionException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
