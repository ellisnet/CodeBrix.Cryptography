using System;
using System.Runtime.Serialization;

namespace CodeBrix.Cryptography.Tls; //was previously: Org.BouncyCastle.Tls;

[Serializable]
public class TlsFatalAlert
    : TlsException
{
    private static string GetMessage(short alertDescription, string detailMessage)
    {
        string msg = Tls.AlertDescription.GetText(alertDescription);
        if (null != detailMessage)
        {
            msg += "; " + detailMessage;
        }
        return msg;
    }

    protected readonly byte m_alertDescription;

    public TlsFatalAlert(short alertDescription)
        : this(alertDescription, null, null)
    {
    }

    public TlsFatalAlert(short alertDescription, string detailMessage)
        : this(alertDescription, detailMessage, null)
    {
    }

    public TlsFatalAlert(short alertDescription, Exception alertCause)
        : this(alertDescription, null, alertCause)
    {
    }

    public TlsFatalAlert(short alertDescription, string detailMessage, Exception alertCause)
        : base(GetMessage(alertDescription, detailMessage), alertCause)
    {
        if (!TlsUtilities.IsValidUint8(alertDescription))
            throw new ArgumentOutOfRangeException(nameof(alertDescription));

        m_alertDescription = (byte)alertDescription;
    }

    [Obsolete("This API supports obsolete formatter-based serialization. It should not be called or extended by application code.")]
    protected TlsFatalAlert(SerializationInfo info, StreamingContext context)
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
