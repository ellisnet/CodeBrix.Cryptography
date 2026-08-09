using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Security.Certificates; //was previously: Org.BouncyCastle.Security.Certificates;

[Serializable]
public class CertificateException
    : GeneralSecurityException
{
    public CertificateException()
        : base()
    {
    }

    public CertificateException(string message)
        : base(message)
    {
    }

    public CertificateException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected CertificateException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
