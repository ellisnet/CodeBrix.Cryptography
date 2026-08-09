using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Security.Certificates; //was previously: Org.BouncyCastle.Security.Certificates;

[Serializable]
public class CertificateExpiredException
    : CertificateException
{
    public CertificateExpiredException()
        : base()
    {
    }

    public CertificateExpiredException(string message)
        : base(message)
    {
    }

    public CertificateExpiredException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected CertificateExpiredException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
