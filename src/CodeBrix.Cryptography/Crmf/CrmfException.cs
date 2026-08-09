using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Crmf; //was previously: Org.BouncyCastle.Crmf;

[Serializable]
public class CrmfException
    : Exception
{
    public CrmfException()
        : base()
    {
    }

    public CrmfException(string message)
        : base(message)
    {
    }

    public CrmfException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected CrmfException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
