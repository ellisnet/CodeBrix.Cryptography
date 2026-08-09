using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.OpenSsl; //was previously: Org.BouncyCastle.OpenSsl;

[Serializable]
public class PasswordException
    // TODO[api] Change to IOException
#pragma warning disable CS0618 // Type or member is obsolete
    : Security.PasswordException
#pragma warning restore CS0618 // Type or member is obsolete
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
