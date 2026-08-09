using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Security.Certificates; //was previously: Org.BouncyCastle.Security.Certificates;

[Serializable]
public class CertificateEncodingException
    : CertificateException
{
    public CertificateEncodingException()
        : base()
    {
    }

    public CertificateEncodingException(string message)
        : base(message)
    {
    }

    public CertificateEncodingException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected CertificateEncodingException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
