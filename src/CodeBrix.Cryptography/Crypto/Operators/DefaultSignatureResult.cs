using System;

namespace CodeBrix.Cryptography.Crypto.Operators; //was previously: Org.BouncyCastle.Crypto.Operators;

public sealed class DefaultSignatureResult
    : IBlockResult
{
    private readonly ISigner m_signer;

    public DefaultSignatureResult(ISigner signer)
    {
        m_signer = signer;
    }

    public byte[] Collect() => m_signer.GenerateSignature();

    public int Collect(byte[] buf, int off)
    {
        byte[] signature = Collect();
        signature.CopyTo(buf, off);
        return signature.Length;
    }

    public int Collect(Span<byte> output)
    {
        byte[] signature = Collect();
        signature.CopyTo(output);
        return signature.Length;
    }

    public int GetMaxResultLength() => m_signer.GetMaxSignatureSize();
}
