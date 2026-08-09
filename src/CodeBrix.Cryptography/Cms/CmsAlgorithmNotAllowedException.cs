using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

[Serializable]
public class CmsAlgorithmNotAllowedException
    : CmsException
{
    public CmsAlgorithmNotAllowedException()
        : base()
    {
    }

    public CmsAlgorithmNotAllowedException(string message)
        : base(message)
    {
    }

    public CmsAlgorithmNotAllowedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected CmsAlgorithmNotAllowedException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
