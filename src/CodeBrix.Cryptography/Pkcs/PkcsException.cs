using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Pkcs; //was previously: Org.BouncyCastle.Pkcs;

/// <summary>Base exception for PKCS related issues.</summary>
[Serializable]
public class PkcsException
    : Exception
{
    public PkcsException()
        : base()
    {
    }

    public PkcsException(string message)
        : base(message)
    {
    }

    public PkcsException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected PkcsException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
