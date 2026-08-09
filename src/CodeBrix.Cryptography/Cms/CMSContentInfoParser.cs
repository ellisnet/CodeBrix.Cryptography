using System;
using System.IO;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Cms;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

// TODO[api] Make abstract
public class CmsContentInfoParser
    : IDisposable
{
    protected ContentInfoParser contentInfo;
    protected Stream data;

    protected CmsContentInfoParser(Stream data)
    {
        this.data = data ?? throw new ArgumentNullException(nameof(data));

        try
        {
            Asn1StreamParser inStream = new Asn1StreamParser(data);

            this.contentInfo = new ContentInfoParser((Asn1SequenceParser)inStream.ReadObject());
        }
        catch (IOException e)
        {
            throw new CmsException("IOException reading content.", e);
        }
        catch (InvalidCastException e)
        {
            throw new CmsException("Unexpected object reading content.", e);
        }
    }

    [Obsolete("Dispose instead")]
    public void Close()
    {
        Dispose();
    }

    #region IDisposable

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            data.Dispose();
        }
    }

    #endregion
}
