using System;
using System.IO;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.IO;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

public class CmsProcessableInputStream
    : CmsProcessable, CmsReadable
{
    private readonly Stream m_input;

    private bool used = false;

    public CmsProcessableInputStream(Stream input)
    {
        m_input = input;
    }

    public virtual Stream GetInputStream()
    {
        CheckSingleUsage();

        return m_input;
    }

    public virtual void Write(Stream output)
    {
        CheckSingleUsage();

        using (m_input)
        {
            Streams.PipeAll(m_input, output);
        }
    }

    protected virtual void CheckSingleUsage()
    {
        lock (this)
        {
            if (used)
                throw new InvalidOperationException("CmsProcessableInputStream can only be used once");

            used = true;
        }
    }
}
