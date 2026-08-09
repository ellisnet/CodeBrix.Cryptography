using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Cmp; //was previously: Org.BouncyCastle.Cmp;

[Serializable]
public class CmpException
    : Exception
{
    public CmpException()
        : base()
    {
    }

    public CmpException(string message)
        : base(message)
    {
    }

    public CmpException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected CmpException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
