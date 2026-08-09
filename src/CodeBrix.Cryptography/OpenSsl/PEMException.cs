using System;
using System.IO;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.OpenSsl; //was previously: Org.BouncyCastle.OpenSsl;

[Serializable]
public class PemException
    : IOException
{
    public PemException()
        : base()
    {
    }

    public PemException(string message)
        : base(message)
    {
    }

    public PemException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected PemException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
