using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Tsp; //was previously: Org.BouncyCastle.Tsp;

/// <summary>
/// Exception thrown if a TSP request or response fails to validate.
/// </summary>
/// <remarks>
/// If a failure code is associated with the exception it can be retrieved using the <see cref="FailureCode"/>
/// property.
/// </remarks>
[Serializable]
public class TspValidationException
    : TspException
{
    // TODO[api] Make private
    protected readonly int m_failureCode;

    public TspValidationException(string message)
        : this(message, -1)
    {
    }

    public TspValidationException(string message, int failureCode)
        : base(message)
    {
        m_failureCode = failureCode;
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected TspValidationException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
        m_failureCode = info.GetInt32("failureCode");
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    public override void GetObjectData(SerializationInfo info, StreamingContext context)
    {
        base.GetObjectData(info, context);
        info.AddValue("failureCode", m_failureCode);
    }

    /// <returns>The failure code associated with this exception, if one is set.</returns>
    public int FailureCode => m_failureCode;
}
