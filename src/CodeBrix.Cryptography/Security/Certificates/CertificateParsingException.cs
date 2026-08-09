using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Security.Certificates; //was previously: Org.BouncyCastle.Security.Certificates;

[Serializable]
public class CertificateParsingException
    : CertificateException
{
    public CertificateParsingException()
        : base()
    {
    }

    public CertificateParsingException(string message)
        : base(message)
    {
    }

    public CertificateParsingException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected CertificateParsingException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
