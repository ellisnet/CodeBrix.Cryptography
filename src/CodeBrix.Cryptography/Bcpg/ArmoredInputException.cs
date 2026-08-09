using System;
using System.IO;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Bcpg; //was previously: Org.BouncyCastle.Bcpg;

[Serializable]
public class ArmoredInputException
    : IOException
{
    public ArmoredInputException()
        : base()
    {
    }

    public ArmoredInputException(string message)
        : base(message)
    {
    }

    public ArmoredInputException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected ArmoredInputException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
