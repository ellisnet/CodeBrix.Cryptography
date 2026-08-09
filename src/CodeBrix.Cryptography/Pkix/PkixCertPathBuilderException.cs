using System;
using System.Runtime.Serialization;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Pkix; //was previously: Org.BouncyCastle.Pkix;

[Serializable]
public class PkixCertPathBuilderException
    : GeneralSecurityException
{
    public PkixCertPathBuilderException()
        : base()
    {
    }

    public PkixCertPathBuilderException(string message)
        : base(message)
    {
    }

    public PkixCertPathBuilderException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected PkixCertPathBuilderException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
