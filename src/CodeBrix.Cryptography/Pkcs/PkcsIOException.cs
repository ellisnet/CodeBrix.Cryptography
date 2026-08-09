using System;
using System.IO;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Pkcs; //was previously: Org.BouncyCastle.Pkcs;

/// <summary>Base exception for parsing related issues in the PKCS namespace.</summary>
[Serializable]
public class PkcsIOException
    : IOException
{
    public PkcsIOException()
        : base()
    {
    }

    public PkcsIOException(string message)
        : base(message)
    {
    }

    public PkcsIOException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected PkcsIOException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
