using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Security.Certificates; //was previously: Org.BouncyCastle.Security.Certificates;

[Serializable]
public class CertificateNotYetValidException
    : CertificateException
{
    public CertificateNotYetValidException()
        : base()
    {
    }

    public CertificateNotYetValidException(string message)
        : base(message)
    {
    }

    public CertificateNotYetValidException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected CertificateNotYetValidException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
