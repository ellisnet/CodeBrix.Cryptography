using System;
using System.IO;

namespace CodeBrix.Cryptography.Utilities.IO; //was previously: Org.BouncyCastle.Utilities.IO;

internal sealed class LimitedInputStream
    : BaseInputStream
{
    private readonly Stream m_stream;
    private readonly bool m_leaveOpen;
    private long m_currentLimit;

    internal LimitedInputStream(long limit, Stream stream, bool leaveOpen = false)
    {
        m_stream = stream;
        m_leaveOpen = leaveOpen;
        m_currentLimit = limit;
    }

    internal long CurrentLimit => m_currentLimit;

    public override int Read(byte[] buffer, int offset, int count)
    {
        return Read(buffer.AsSpan(offset, count));
    }

    public override int Read(Span<byte> buffer)
    {
        int numRead = m_stream.Read(buffer);
        if (numRead > 0)
        {
            if ((m_currentLimit -= numRead) < 0)
                throw new StreamOverflowException("Data Overflow");
        }
        return numRead;
    }

    public override int ReadByte()
    {
        int b = m_stream.ReadByte();
        if (b >= 0)
        {
            if (--m_currentLimit < 0)
                throw new StreamOverflowException("Data Overflow");
        }
        return b;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            if (!m_leaveOpen)
            {
                m_stream.Dispose();
            }
        }

        base.Dispose(disposing);
    }
}
