using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

[Serializable]
public class CmsAttributeTableGenerationException
    : CmsException
{
    public CmsAttributeTableGenerationException()
        : base()
    {
    }

    public CmsAttributeTableGenerationException(string message)
        : base(message)
    {
    }

    public CmsAttributeTableGenerationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected CmsAttributeTableGenerationException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
