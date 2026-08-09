using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Pkix; //was previously: Org.BouncyCastle.Pkix;

[Serializable]
public class PkixNameConstraintValidatorException
    : Exception
{
    public PkixNameConstraintValidatorException()
        : base()
    {
    }

    public PkixNameConstraintValidatorException(string message)
        : base(message)
    {
    }

    public PkixNameConstraintValidatorException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected PkixNameConstraintValidatorException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
