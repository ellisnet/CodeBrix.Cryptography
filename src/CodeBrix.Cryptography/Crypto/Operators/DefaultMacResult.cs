using System;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Crypto.Operators; //was previously: Org.BouncyCastle.Crypto.Operators;

public sealed class DefaultMacResult
    : IBlockResult
{
    private readonly IMac m_mac;

    public DefaultMacResult(IMac mac)
    {
        m_mac = mac;
    }

    public byte[] Collect() => MacUtilities.DoFinal(m_mac);

    public int Collect(byte[] buf, int off) => m_mac.DoFinal(buf, off);

    public int Collect(Span<byte> output) => m_mac.DoFinal(output);

    public int GetMaxResultLength() => m_mac.GetMacSize();
}
