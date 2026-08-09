using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

[Serializable]
public class CmsVerifierCertificateNotValidException
    : CmsException
{
    public CmsVerifierCertificateNotValidException()
        : base()
    {
    }

    public CmsVerifierCertificateNotValidException(string message)
        : base(message)
    {
    }

    public CmsVerifierCertificateNotValidException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected CmsVerifierCertificateNotValidException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
