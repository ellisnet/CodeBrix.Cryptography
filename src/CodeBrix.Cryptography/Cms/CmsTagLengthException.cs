using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

[Serializable]
public class CmsTagLengthException
    : CmsException
{
    public CmsTagLengthException()
        : base()
    {
    }

    public CmsTagLengthException(string message)
        : base(message)
    {
    }

    public CmsTagLengthException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected CmsTagLengthException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
