using System;
using System.IO;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

[Serializable]
public class CmsStreamException
    : IOException
{
    public CmsStreamException()
        : base()
    {
    }

    public CmsStreamException(string message)
        : base(message)
    {
    }

    public CmsStreamException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected CmsStreamException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
