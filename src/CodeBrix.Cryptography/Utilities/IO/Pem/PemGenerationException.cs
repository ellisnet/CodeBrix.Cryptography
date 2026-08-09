using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Utilities.IO.Pem; //was previously: Org.BouncyCastle.Utilities.IO.Pem;

[Serializable]
public class PemGenerationException
    : Exception
{
    public PemGenerationException()
        : base()
    {
    }

    public PemGenerationException(string message)
        : base(message)
    {
    }

    public PemGenerationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected PemGenerationException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
