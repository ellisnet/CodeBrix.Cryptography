using System;
using System.Diagnostics;
using CodeBrix.Cryptography.Math.EC.Rfc8032;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities;
using F = CodeBrix.Cryptography.Math.EC.Rfc7748.X25519Field;

namespace CodeBrix.Cryptography.Math.EC.Rfc7748; //was previously: Org.BouncyCastle.Math.EC.Rfc7748;

public static class X25519
{
    public const int PointSize = 32;
    public const int ScalarSize = 32;

    private const int C_A = 486662;
    private const int C_A24 = (C_A + 2)/4;

    //private static readonly int[] SqrtNeg486664 = { 0x03457E06, 0x03812ABF, 0x01A82CC6, 0x028A5BE8, 0x018B43A7,
    //    0x03FC4F7E, 0x02C23700, 0x006BBD27, 0x03A30500, 0x001E4DDB };

    public static bool CalculateAgreement(byte[] k, int kOff, byte[] u, int uOff, byte[] r, int rOff)
    {
        ScalarMult(k, kOff, u, uOff, r, rOff);
        return !Arrays.AreAllZeroes(r, rOff, PointSize);
    }

    public static bool CalculateAgreement(ReadOnlySpan<byte> k, ReadOnlySpan<byte> u, Span<byte> r)
    {
        r = r[..PointSize];
        ScalarMult(k, u, r);
        return !Arrays.AreAllZeroes(r);
    }

    public static void ClampPrivateKey(byte[] k)
    {
        ClampPrivateKey(k.AsSpan(0, ScalarSize));
    }

    public static void ClampPrivateKey(Span<byte> k)
    {
        if (k.Length != ScalarSize)
            throw new ArgumentException(nameof(k));

        k[0             ] &= 0xF8;
        k[ScalarSize - 1] &= 0x7F;
        k[ScalarSize - 1] |= 0x40;
    }

    private static void DecodeScalar(ReadOnlySpan<byte> k, Span<uint> n)
    {
        for (int i = 0; i < 8; ++i)
        {
            n[i] = F.Decode32(k[(i * 4)..]);
        }

        n[0] &= 0xFFFFFFF8U;
        n[7] &= 0x7FFFFFFFU;
        n[7] |= 0x40000000U;
    }

    public static void GeneratePrivateKey(SecureRandom random, byte[] k)
    {
        GeneratePrivateKey(random, k.AsSpan(0, ScalarSize));
    }

    public static void GeneratePrivateKey(SecureRandom random, Span<byte> k)
    {
        if (random == null)
            throw new ArgumentNullException(nameof(random));
        if (k.Length != ScalarSize)
            throw new ArgumentException(nameof(k));

        random.NextBytes(k);

        ClampPrivateKey(k);
    }

    public static void GeneratePublicKey(byte[] k, int kOff, byte[] r, int rOff) =>
        ScalarMultBase(k, kOff, r, rOff);

    public static void GeneratePublicKey(ReadOnlySpan<byte> k, Span<byte> r) => ScalarMultBase(k, r);

    private static void PointDouble(int[] x, int[] z)
    {
        int[] a = F.Create();
        int[] b = F.Create();

        F.Apm(x, z, a, b);
        F.Sqr(a, a);
        F.Sqr(b, b);
        F.Mul(a, b, x);
        F.Sub(a, b, a);
        F.Mul(a, C_A24, z);
        F.Add(z, b, z);
        F.Mul(z, a, z);
    }

    public static void Precompute() => Ed25519.Precompute();

    public static void ScalarMult(byte[] k, int kOff, byte[] u, int uOff, byte[] r, int rOff)
    {
        ScalarMult(k.AsSpan(kOff, ScalarSize), u.AsSpan(uOff, PointSize), r.AsSpan(rOff, PointSize));
    }

    public static void ScalarMult(ReadOnlySpan<byte> k, ReadOnlySpan<byte> u, Span<byte> r)
    {
        // TODO[api] Exact length check
        if (k.Length < ScalarSize)
            throw new ArgumentException(nameof(k));
        // TODO[api] Exact length check
        if (u.Length < PointSize)
            throw new ArgumentException(nameof(u));
        // TODO[api] Exact length check
        if (r.Length < PointSize)
            throw new ArgumentException(nameof(r));

        uint[] n = new uint[8];     DecodeScalar(k, n);

        int[] x1 = F.Create();      F.Decode255(u, x1);
        int[] x2 = F.Create();      F.Copy(x1, 0, x2, 0);
        int[] z2 = F.Create();      z2[0] = 1;
        int[] x3 = F.Create();      x3[0] = 1;
        int[] z3 = F.Create();

        int[] t1 = F.Create();
        int[] t2 = F.Create();

        Debug.Assert(n[7] >> 30 == 1U);

        int bit = 254, swap = 1;
        do
        {
            F.Apm(x3, z3, t1, x3);
            F.Apm(x2, z2, z3, x2);
            F.Mul(t1, x2, t1);
            F.Mul(x3, z3, x3);
            F.Sqr(z3, z3);
            F.Sqr(x2, x2);

            F.Sub(z3, x2, t2);
            F.Mul(t2, C_A24, z2);
            F.Add(z2, x2, z2);
            F.Mul(z2, t2, z2);
            F.Mul(x2, z3, x2);

            F.Apm(t1, x3, x3, z3);
            F.Sqr(x3, x3);
            F.Sqr(z3, z3);
            F.Mul(z3, x1, z3);

            --bit;

            int word = bit >> 5, shift = bit & 0x1F;
            int kt = (int)(n[word] >> shift) & 1;
            swap ^= kt;
            F.CSwap(swap, x2, x3);
            F.CSwap(swap, z2, z3);
            swap = kt;
        }
        while (bit >= 3);

        Debug.Assert(swap == 0);

        for (int i = 0; i < 3; ++i)
        {
            PointDouble(x2, z2);
        }

        F.Inv(z2, z2);
        F.Mul(x2, z2, x2);

        F.Normalize(x2);
        F.Encode(x2, r);
    }

    public static void ScalarMultBase(byte[] k, int kOff, byte[] r, int rOff)
    {
        ScalarMultBase(k.AsSpan(kOff, ScalarSize), r.AsSpan(rOff, PointSize));
    }

    public static void ScalarMultBase(ReadOnlySpan<byte> k, Span<byte> r)
    {
        // Equivalent (but much slower)
        //Span<byte> u = stackalloc byte[PointSize];
        //u[0] = 9;

        //ScalarMult(k, u, r);

        // TODO[api] Exact length check
        if (k.Length < ScalarSize)
            throw new ArgumentException(nameof(k));
        // TODO[api] Exact length check
        if (r.Length < PointSize)
            throw new ArgumentException(nameof(r));

        int[] y = F.Create();
        int[] z = F.Create();

        Ed25519.ScalarMultBaseYZ(k, y.AsSpan(), z.AsSpan());

        F.Apm(z, y, y, z);

        F.Inv(z, z);
        F.Mul(y, z, y);

        F.Normalize(y);
        F.Encode(y, r);
    }
}
