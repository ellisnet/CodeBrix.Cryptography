using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Tls; //was previously: Org.BouncyCastle.Tls;

[Serializable]
public class TlsFatalAlertReceived
    : TlsException
{
    protected readonly byte m_alertDescription;

    public TlsFatalAlertReceived(short alertDescription)
        : base(Tls.AlertDescription.GetText(alertDescription))
    {
        if (!TlsUtilities.IsValidUint8(alertDescription))
            throw new ArgumentOutOfRangeException(nameof(alertDescription));

        m_alertDescription = (byte)alertDescription;
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected TlsFatalAlertReceived(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
        m_alertDescription = info.GetByte("alertDescription");
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    public override void GetObjectData(SerializationInfo info, StreamingContext context)
    {
        base.GetObjectData(info, context);
        info.AddValue("alertDescription", m_alertDescription);
    }

    public virtual short AlertDescription
    {
        get { return m_alertDescription; }
    }
}
