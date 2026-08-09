using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Bcpg.OpenPgp; //was previously: Org.BouncyCastle.Bcpg.OpenPgp;

/// <summary>Generic exception class for PGP encoding/decoding problems.</summary>
[Serializable]
public class PgpException
    : Exception
{
    public PgpException()
        : base()
    {
    }

    public PgpException(string message)
        : base(message)
    {
    }

    public PgpException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected PgpException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
