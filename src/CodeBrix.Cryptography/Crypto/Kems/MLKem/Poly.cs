using System;

namespace CodeBrix.Cryptography.Crypto.Kems.MLKem; //was previously: Org.BouncyCastle.Crypto.Kems.MLKem;

internal sealed class Poly
{
    internal readonly short[] m_coeffs = new short[MLKemEngine.N];

    internal short[] Coeffs => m_coeffs;

    internal void GetNoiseEta2(IXof xof, ReadOnlySpan<byte> seed, byte nonce)
    {
        Span<byte> buf = stackalloc byte[2 * MLKemEngine.N / 4];
        Prf(xof, seed, nonce, buf);
        Cbd.Eta2(m_coeffs.AsSpan(), buf);
    }

    internal void GetNoiseEta3(IXof xof, ReadOnlySpan<byte> seed, byte nonce)
    {
        Span<byte> buf = stackalloc byte[3 * MLKemEngine.N / 4];
        Prf(xof, seed, nonce, buf);
        Cbd.Eta3(m_coeffs.AsSpan(), buf);
    }

    private static void Prf(IXof xof, ReadOnlySpan<byte> seed, byte nonce, Span<byte> output)
    {
        xof.BlockUpdate(seed[..MLKemEngine.SymBytes]);
        xof.Update(nonce);
        xof.OutputFinal(output);
    }

    internal void PolyNtt()
    {
        Ntt.NTT(Coeffs);
        PolyReduce();
    }

    internal void PolyInverseNttToMont()
    {
        Ntt.InvNTT(Coeffs);
    }

    internal static void BaseMultMontgomery(Poly r, Poly a, Poly b)
    {
        for (int i = 0; i < MLKemEngine.N / 4; i++)
        {
            Ntt.BaseMult(r.Coeffs, 4 * i,
                a.Coeffs[4 * i], a.Coeffs[4 * i + 1],
                b.Coeffs[4 * i], b.Coeffs[4 * i + 1],
                Ntt.Zetas[64 + i]);
            Ntt.BaseMult(r.Coeffs, 4 * i + 2,
                a.Coeffs[4 * i + 2], a.Coeffs[4 * i + 3],
                b.Coeffs[4 * i + 2], b.Coeffs[4 * i + 3],
                (short) (-1  * Ntt.Zetas[64 + i]));
        }
    }

    internal void ToMont()
    {
        const short f = (short) ((1UL << 32) % MLKemEngine.Q);
        for (int i = 0; i < MLKemEngine.N; i++)
        {
            Coeffs[i] = Reduce.MontgomeryReduce(Coeffs[i] * f);
        }
    }

    internal void Add(Poly a)
    {
        for (int i = 0; i < MLKemEngine.N; i++)
        {
            Coeffs[i] += a.Coeffs[i];
        }
    }

    internal void Subtract(Poly a)
    {
        for (int i = 0; i < MLKemEngine.N; i++)
        {
            Coeffs[i] = (short)(a.Coeffs[i] - Coeffs[i]);
        }
    }

    internal void PolyReduce()
    {
        for (int i = 0; i < MLKemEngine.N; i++)
        {
            Coeffs[i] = Reduce.BarrettReduce(Coeffs[i]);
        }
    }

    internal void CompressPoly128(Span<byte> rBuf)
    {
        int pos = 0;

        Span<byte> t = stackalloc byte[8];

        CondSubQ();

        for (int i = 0; i < MLKemEngine.N / 8; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                int c_j = m_coeffs[8 * i + j];

                // Avoid non-constant-time division by Q.
                //t[j] = (byte)((((c_j << 4) + (MLKemEngine.Q / 2)) / MLKemEngine.Q) & 15);
                t[j] = (byte)((((c_j + (MLKemEngine.Q >> 5)) * 315) >> 16) & 0xF);
            }
            rBuf[pos + 0] = (byte)(t[0] | (t[1] << 4));
            rBuf[pos + 1] = (byte)(t[2] | (t[3] << 4));
            rBuf[pos + 2] = (byte)(t[4] | (t[5] << 4));
            rBuf[pos + 3] = (byte)(t[6] | (t[7] << 4));
            pos += 4;
        }
    }

    internal void CompressPoly160(Span<byte> rBuf)
    {
        int pos = 0;

        Span<byte> t = stackalloc byte[8];

        CondSubQ();

        for (int i = 0; i < MLKemEngine.N / 8; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                int c_j = m_coeffs[8 * i + j];

                // Avoid non-constant-time division by Q.
                //t[j] = (byte)((((c_j << 5) + (MLKemEngine.Q / 2)) / MLKemEngine.Q) & 31);
                t[j] = (byte)((((c_j + (MLKemEngine.Q >> 6)) * 630) >> 16) & 0x1F);
            }
            rBuf[pos + 0] = (byte)((t[0] >> 0) | (t[1] << 5));
            rBuf[pos + 1] = (byte)((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
            rBuf[pos + 2] = (byte)((t[3] >> 1) | (t[4] << 4));
            rBuf[pos + 3] = (byte)((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
            rBuf[pos + 4] = (byte)((t[6] >> 2) | (t[7] << 3));
            pos += 5;
        }
    }

    internal void DecompressPoly128(ReadOnlySpan<byte> cBuf)
    {
        int pos = 0;

        for (int i = 0; i < MLKemEngine.N / 2; i++)
        {
            Coeffs[2 * i + 0] = (short)((((short)((cBuf[pos] & 0xFF) & 15) * MLKemEngine.Q) + 8) >> 4);
            Coeffs[2 * i + 1] = (short)((((short)((cBuf[pos] & 0xFF) >> 4) * MLKemEngine.Q) + 8) >> 4);
            pos += 1;
        }
    }

    internal void DecompressPoly160(ReadOnlySpan<byte> cBuf)
    {
        int pos = 0;

        byte[] t = new byte[8];
        for (int i = 0; i < MLKemEngine.N / 8; i++)
        {
            t[0] = (byte)((cBuf[pos + 0] & 0xFF) >> 0);
            t[1] = (byte)(((cBuf[pos + 0] & 0xFF) >> 5) | ((cBuf[pos + 1] & 0xFF) << 3));
            t[2] = (byte)((cBuf[pos + 1] & 0xFF) >> 2);
            t[3] = (byte)(((cBuf[pos + 1] & 0xFF) >> 7) | ((cBuf[pos + 2] & 0xFF) << 1));
            t[4] = (byte)(((cBuf[pos + 2] & 0xFF) >> 4) | ((cBuf[pos + 3] & 0xFF) << 4));
            t[5] = (byte)((cBuf[pos + 3] & 0xFF) >> 1);
            t[6] = (byte)(((cBuf[pos + 3] & 0xFF) >> 6) | ((cBuf[pos + 4] & 0xFF) << 2));
            t[7] = (byte)((cBuf[pos + 4] & 0xFF) >> 3);
            pos += 5;
            for (int j = 0; j < 8; j++)
            {
                Coeffs[8 * i + j] = (short)(((t[j] & 31) * MLKemEngine.Q + 16) >> 5);
            }
        }
    }

    internal void FromBytes(ReadOnlySpan<byte> a)
    {
        for (int i = 0; i < MLKemEngine.N / 2; i++)
        {
            ushort a0 = a[3 * i + 0];
            ushort a1 = a[3 * i + 1];
            ushort a2 = a[3 * i + 2];
            Coeffs[2 * i + 0] = (short)(((a0 >> 0) | (a1 << 8)) & 0xFFF);
            Coeffs[2 * i + 1] = (short)(((a1 >> 4) | (a2 << 4)) & 0xFFF);
        }
    }

    internal void ToBytes(Span<byte> r)
    {
        CondSubQ();

        for (int i = 0; i < MLKemEngine.N / 2; i++)
        {
            ushort t0 = (ushort)Coeffs[2 * i + 0];
            ushort t1 = (ushort)Coeffs[2 * i + 1];
            r[3 * i + 0] = (byte)t0;
            r[3 * i + 1] = (byte)((t0 >> 8) | (t1 << 4));
            r[3 * i + 2] = (byte)(t1 >> 4);
        }
    }

    internal void ToMsg(Span<byte> msg)
    {
        const int Lower = MLKemEngine.Q >> 2;
        const int Upper = MLKemEngine.Q - Lower;

        CondSubQ();

        for (int i = 0; i < MLKemEngine.N / 8; i++)
        {
            uint m_i = 0U;
            for (int j = 0; j < 8; j++)
            {
                int c_j = Coeffs[8 * i + j];

                // Avoid non-constant-time division by Q.
                //int t = (((c_j << 1) + (MLKemEngine.Q / 2)) / MLKemEngine.Q) & 1;
                uint t = (uint)((Lower - c_j) & (c_j - Upper)) >> 31;

                m_i |= t << j;
            }
            msg[i] = (byte)m_i;
        }
    }

    internal void FromMsg(ReadOnlySpan<byte> msg)
    {
        for (int i = 0; i < MLKemEngine.N / 8; i++)
        {
            int msg_i = msg[i];
            for (int j = 0; j < 8; j++)
            {
                short mask = (short)-((msg_i >> j) & 1);
                Coeffs[8 * i + j] = (short)(mask & ((MLKemEngine.Q + 1) / 2));
            }
        }
    }

    internal void CondSubQ()
    {
        for (int i = 0; i < MLKemEngine.N; i++)
        {
            Coeffs[i] = Reduce.CondSubQ(Coeffs[i]);
        }
    }

    internal static int CheckModulus(ReadOnlySpan<byte> a)
    {
        int result = -1;
        for (int i = 0; i < MLKemEngine.N / 2; i++)
        {
            ushort a0 = a[3 * i + 0];
            ushort a1 = a[3 * i + 1];
            ushort a2 = a[3 * i + 2];
            short c0 = (short)(((a0 >> 0) | (a1 << 8)) & 0xFFF);
            short c1 = (short)(((a1 >> 4) | (a2 << 4)) & 0xFFF);
            result &= Reduce.CheckModulus(c0);
            result &= Reduce.CheckModulus(c1);
        }
        return result;
    }
}
