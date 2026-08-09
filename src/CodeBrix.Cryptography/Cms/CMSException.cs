using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

[Serializable]
public class CmsException
    : Exception
{
    public CmsException()
        : base()
    {
    }

    public CmsException(string message)
        : base(message)
    {
    }

    public CmsException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected CmsException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
