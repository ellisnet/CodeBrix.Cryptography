using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Bcpg.OpenPgp; //was previously: Org.BouncyCastle.Bcpg.OpenPgp;

/// <summary>Thrown if the key checksum is invalid.</summary>
[Serializable]
public class PgpKeyValidationException
    : PgpException
{
    public PgpKeyValidationException()
        : base()
    {
    }

    public PgpKeyValidationException(string message)
        : base(message)
    {
    }

    public PgpKeyValidationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected PgpKeyValidationException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
