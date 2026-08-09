using System;
using System.IO;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Security; //was previously: Org.BouncyCastle.Security;

[Obsolete("Use CodeBrix.Cryptography.OpenSsl.PasswordException instead")]
[Serializable]
public class PasswordException
    : IOException
{
    public PasswordException()
        : base()
    {
    }

    public PasswordException(string message)
        : base(message)
    {
    }

    public PasswordException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected PasswordException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
