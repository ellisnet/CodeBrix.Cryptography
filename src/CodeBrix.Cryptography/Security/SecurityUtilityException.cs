using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Security; //was previously: Org.BouncyCastle.Security;

[Serializable]
public class SecurityUtilityException
    : Exception
{
    public SecurityUtilityException()
        : base()
    {
    }

    public SecurityUtilityException(string message)
        : base(message)
    {
    }

    public SecurityUtilityException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected SecurityUtilityException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
