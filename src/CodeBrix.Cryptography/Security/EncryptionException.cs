using System;
using System.IO;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Security; //was previously: Org.BouncyCastle.Security;

[Obsolete("Use CodeBrix.Cryptography.OpenSsl.EncryptionException instead")]
[Serializable]
public class EncryptionException
    : IOException
{
    public EncryptionException()
        : base()
    {
    }

    public EncryptionException(string message)
        : base(message)
    {
    }

    public EncryptionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected EncryptionException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
