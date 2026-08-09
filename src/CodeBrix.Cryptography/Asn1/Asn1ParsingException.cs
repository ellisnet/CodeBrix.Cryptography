using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Asn1; //was previously: Org.BouncyCastle.Asn1;

[Serializable]
public class Asn1ParsingException
    : InvalidOperationException
{
    public Asn1ParsingException()
        : base()
    {
    }

    public Asn1ParsingException(string message)
        : base(message)
    {
    }

    public Asn1ParsingException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected Asn1ParsingException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
