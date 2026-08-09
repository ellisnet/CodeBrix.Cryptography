using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Security; //was previously: Org.BouncyCastle.Security;

[Serializable]
public class SignatureException
    : GeneralSecurityException
{
    public SignatureException()
        : base()
    {
    }

    public SignatureException(string message)
        : base(message)
    {
    }

    public SignatureException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected SignatureException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
