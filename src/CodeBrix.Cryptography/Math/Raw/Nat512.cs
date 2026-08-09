using System;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CodeBrix.Cryptography.Math.Raw; //was previously: Org.BouncyCastle.Math.Raw;

internal static class Nat512
{
    public static void Mul(uint[] x, uint[] y, uint[] zz)
    {
        Nat256.Mul(x, y, zz);
        Nat256.Mul(x, 8, y, 8, zz, 16);

        uint c24 = Nat256.AddToEachOther(zz, 8, zz, 16);
        uint c16 = c24 + Nat256.AddTo(zz, 0, zz, 8, 0U);
        c24 += Nat256.AddTo(zz, 24, zz, 16, c16);

        uint[] dx = Nat256.Create(), dy = Nat256.Create();
        bool neg = Nat256.Diff(x, 8, x, 0, dx, 0) != Nat256.Diff(y, 8, y, 0, dy, 0);

        uint[] tt = Nat256.CreateExt();
        Nat256.Mul(dx, dy, tt);

        c24 += neg ? Nat.AddTo(16, tt, 0, zz, 8) : (uint)Nat.SubFrom(16, tt, 0, zz, 8);
        Nat.AddWordAt(32, c24, zz, 24);
    }

    public static void Square(uint[] x, uint[] zz)
    {
        Nat256.Square(x, zz);
        Nat256.Square(x, 8, zz, 16);

        uint c24 = Nat256.AddToEachOther(zz, 8, zz, 16);
        uint c16 = c24 + Nat256.AddTo(zz, 0, zz, 8, 0U);
        c24 += Nat256.AddTo(zz, 24, zz, 16, c16);

        uint[] dx = Nat256.Create();
        Nat256.Diff(x, 8, x, 0, dx, 0);

        uint[] m = Nat256.CreateExt();
        Nat256.Square(dx, m);

        c24 += (uint)Nat.SubFrom(16, m, 0, zz, 8);
        Nat.AddWordAt(32, c24, zz, 24);
    }

    public static void Xor(uint[] x, uint y, uint[] z)
    {
        Xor(x.AsSpan(), y, z.AsSpan());
    }

    public static void Xor(uint[] x, int xOff, uint y, uint[] z, int zOff)
    {
        Xor(x.AsSpan(xOff), y, z.AsSpan(zOff));
    }

    public static void Xor(ReadOnlySpan<uint> x, uint y, Span<uint> z)
    {
        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..16]);
            var Z = MemoryMarshal.AsBytes(z[..16]);

            var X0 = MemoryMarshal.Read<Vector256<byte>>(X[0x00..0x20]);
            var X1 = MemoryMarshal.Read<Vector256<byte>>(X[0x20..0x40]);

            var Y_ = Vector256.Create(y).AsByte();

            var Z0 = Avx2.Xor(X0, Y_);
            var Z1 = Avx2.Xor(X1, Y_);

            MemoryMarshal.Write(Z[0x00..0x20], in Z0);
            MemoryMarshal.Write(Z[0x20..0x40], in Z1);
            return;
        }

        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..16]);
            var Z = MemoryMarshal.AsBytes(z[..16]);

            var X0 = MemoryMarshal.Read<Vector128<byte>>(X[0x00..0x10]);
            var X1 = MemoryMarshal.Read<Vector128<byte>>(X[0x10..0x20]);
            var X2 = MemoryMarshal.Read<Vector128<byte>>(X[0x20..0x30]);
            var X3 = MemoryMarshal.Read<Vector128<byte>>(X[0x30..0x40]);

            var Y_ = Vector128.Create(y).AsByte();

            var Z0 = Sse2.Xor(X0, Y_);
            var Z1 = Sse2.Xor(X1, Y_);
            var Z2 = Sse2.Xor(X2, Y_);
            var Z3 = Sse2.Xor(X3, Y_);

            MemoryMarshal.Write(Z[0x00..0x10], in Z0);
            MemoryMarshal.Write(Z[0x10..0x20], in Z1);
            MemoryMarshal.Write(Z[0x20..0x30], in Z2);
            MemoryMarshal.Write(Z[0x30..0x40], in Z3);
            return;
        }

        for (int i = 0; i < 16; i += 4)
        {
            z[i + 0] = x[i + 0] ^ y;
            z[i + 1] = x[i + 1] ^ y;
            z[i + 2] = x[i + 2] ^ y;
            z[i + 3] = x[i + 3] ^ y;
        }
    }

    public static void Xor(uint[] x, uint[] y, uint[] z)
    {
        Xor(x.AsSpan(), y.AsSpan(), z.AsSpan());
    }

    public static void Xor(uint[] x, int xOff, uint[] y, int yOff, uint[] z, int zOff)
    {
        Xor(x.AsSpan(xOff), y.AsSpan(yOff), z.AsSpan(zOff));
    }

    public static void Xor(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
    {
        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..16]);
            var Y = MemoryMarshal.AsBytes(y[..16]);
            var Z = MemoryMarshal.AsBytes(z[..16]);

            var X0 = MemoryMarshal.Read<Vector256<byte>>(X[0x00..0x20]);
            var X1 = MemoryMarshal.Read<Vector256<byte>>(X[0x20..0x40]);

            var Y0 = MemoryMarshal.Read<Vector256<byte>>(Y[0x00..0x20]);
            var Y1 = MemoryMarshal.Read<Vector256<byte>>(Y[0x20..0x40]);

            var Z0 = Avx2.Xor(X0, Y0);
            var Z1 = Avx2.Xor(X1, Y1);

            MemoryMarshal.Write(Z[0x00..0x20], in Z0);
            MemoryMarshal.Write(Z[0x20..0x40], in Z1);
            return;
        }

        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..16]);
            var Y = MemoryMarshal.AsBytes(y[..16]);
            var Z = MemoryMarshal.AsBytes(z[..16]);

            var X0 = MemoryMarshal.Read<Vector128<byte>>(X[0x00..0x10]);
            var X1 = MemoryMarshal.Read<Vector128<byte>>(X[0x10..0x20]);
            var X2 = MemoryMarshal.Read<Vector128<byte>>(X[0x20..0x30]);
            var X3 = MemoryMarshal.Read<Vector128<byte>>(X[0x30..0x40]);

            var Y0 = MemoryMarshal.Read<Vector128<byte>>(Y[0x00..0x10]);
            var Y1 = MemoryMarshal.Read<Vector128<byte>>(Y[0x10..0x20]);
            var Y2 = MemoryMarshal.Read<Vector128<byte>>(Y[0x20..0x30]);
            var Y3 = MemoryMarshal.Read<Vector128<byte>>(Y[0x30..0x40]);

            var Z0 = Sse2.Xor(X0, Y0);
            var Z1 = Sse2.Xor(X1, Y1);
            var Z2 = Sse2.Xor(X2, Y2);
            var Z3 = Sse2.Xor(X3, Y3);

            MemoryMarshal.Write(Z[0x00..0x10], in Z0);
            MemoryMarshal.Write(Z[0x10..0x20], in Z1);
            MemoryMarshal.Write(Z[0x20..0x30], in Z2);
            MemoryMarshal.Write(Z[0x30..0x40], in Z3);
            return;
        }

        for (int i = 0; i < 16; i += 4)
        {
            z[i + 0] = x[i + 0] ^ y[i + 0];
            z[i + 1] = x[i + 1] ^ y[i + 1];
            z[i + 2] = x[i + 2] ^ y[i + 2];
            z[i + 3] = x[i + 3] ^ y[i + 3];
        }
    }

    public static void Xor64(ulong[] x, ulong y, ulong[] z)
    {
        Xor64(x.AsSpan(), y, z.AsSpan());
    }

    public static void Xor64(ulong[] x, int xOff, ulong y, ulong[] z, int zOff)
    {
        Xor64(x.AsSpan(xOff), y, z.AsSpan(zOff));
    }

    public static void Xor64(ReadOnlySpan<ulong> x, ulong y, Span<ulong> z)
    {
        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..8]);
            var Z = MemoryMarshal.AsBytes(z[..8]);

            var X0 = MemoryMarshal.Read<Vector256<byte>>(X[0x00..0x20]);
            var X1 = MemoryMarshal.Read<Vector256<byte>>(X[0x20..0x40]);

            var Y_ = Vector256.Create(y).AsByte();

            var Z0 = Avx2.Xor(X0, Y_);
            var Z1 = Avx2.Xor(X1, Y_);

            MemoryMarshal.Write(Z[0x00..0x20], in Z0);
            MemoryMarshal.Write(Z[0x20..0x40], in Z1);
            return;
        }

        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..8]);
            var Z = MemoryMarshal.AsBytes(z[..8]);

            var X0 = MemoryMarshal.Read<Vector128<byte>>(X[0x00..0x10]);
            var X1 = MemoryMarshal.Read<Vector128<byte>>(X[0x10..0x20]);
            var X2 = MemoryMarshal.Read<Vector128<byte>>(X[0x20..0x30]);
            var X3 = MemoryMarshal.Read<Vector128<byte>>(X[0x30..0x40]);

            var Y_ = Vector128.Create(y).AsByte();

            var Z0 = Sse2.Xor(X0, Y_);
            var Z1 = Sse2.Xor(X1, Y_);
            var Z2 = Sse2.Xor(X2, Y_);
            var Z3 = Sse2.Xor(X3, Y_);

            MemoryMarshal.Write(Z[0x00..0x10], in Z0);
            MemoryMarshal.Write(Z[0x10..0x20], in Z1);
            MemoryMarshal.Write(Z[0x20..0x30], in Z2);
            MemoryMarshal.Write(Z[0x30..0x40], in Z3);
            return;
        }

        for (int i = 0; i < 8; i += 4)
        {
            z[i + 0] = x[i + 0] ^ y;
            z[i + 1] = x[i + 1] ^ y;
            z[i + 2] = x[i + 2] ^ y;
            z[i + 3] = x[i + 3] ^ y;
        }
    }

    public static void Xor64(ulong[] x, ulong[] y, ulong[] z)
    {
        Xor64(x.AsSpan(), y.AsSpan(), z.AsSpan());
    }

    public static void Xor64(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
    {
        Xor64(x.AsSpan(xOff), y.AsSpan(yOff), z.AsSpan(zOff));
    }

    public static void Xor64(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> z)
    {
        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..8]);
            var Y = MemoryMarshal.AsBytes(y[..8]);
            var Z = MemoryMarshal.AsBytes(z[..8]);

            var X0 = MemoryMarshal.Read<Vector256<byte>>(X[0x00..0x20]);
            var X1 = MemoryMarshal.Read<Vector256<byte>>(X[0x20..0x40]);

            var Y0 = MemoryMarshal.Read<Vector256<byte>>(Y[0x00..0x20]);
            var Y1 = MemoryMarshal.Read<Vector256<byte>>(Y[0x20..0x40]);

            var Z0 = Avx2.Xor(X0, Y0);
            var Z1 = Avx2.Xor(X1, Y1);

            MemoryMarshal.Write(Z[0x00..0x20], in Z0);
            MemoryMarshal.Write(Z[0x20..0x40], in Z1);
            return;
        }

        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..8]);
            var Y = MemoryMarshal.AsBytes(y[..8]);
            var Z = MemoryMarshal.AsBytes(z[..8]);

            var X0 = MemoryMarshal.Read<Vector128<byte>>(X[0x00..0x10]);
            var X1 = MemoryMarshal.Read<Vector128<byte>>(X[0x10..0x20]);
            var X2 = MemoryMarshal.Read<Vector128<byte>>(X[0x20..0x30]);
            var X3 = MemoryMarshal.Read<Vector128<byte>>(X[0x30..0x40]);

            var Y0 = MemoryMarshal.Read<Vector128<byte>>(Y[0x00..0x10]);
            var Y1 = MemoryMarshal.Read<Vector128<byte>>(Y[0x10..0x20]);
            var Y2 = MemoryMarshal.Read<Vector128<byte>>(Y[0x20..0x30]);
            var Y3 = MemoryMarshal.Read<Vector128<byte>>(Y[0x30..0x40]);

            var Z0 = Sse2.Xor(X0, Y0);
            var Z1 = Sse2.Xor(X1, Y1);
            var Z2 = Sse2.Xor(X2, Y2);
            var Z3 = Sse2.Xor(X3, Y3);

            MemoryMarshal.Write(Z[0x00..0x10], in Z0);
            MemoryMarshal.Write(Z[0x10..0x20], in Z1);
            MemoryMarshal.Write(Z[0x20..0x30], in Z2);
            MemoryMarshal.Write(Z[0x30..0x40], in Z3);
            return;
        }

        for (int i = 0; i < 8; i += 4)
        {
            z[i + 0] = x[i + 0] ^ y[i + 0];
            z[i + 1] = x[i + 1] ^ y[i + 1];
            z[i + 2] = x[i + 2] ^ y[i + 2];
            z[i + 3] = x[i + 3] ^ y[i + 3];
        }
    }

    public static void XorBothTo(uint[] x, uint[] y, uint[] z)
    {
        XorBothTo(x.AsSpan(), y.AsSpan(), z.AsSpan());
    }

    public static void XorBothTo(uint[] x, int xOff, uint[] y, int yOff, uint[] z, int zOff)
    {
        XorBothTo(x.AsSpan(xOff), y.AsSpan(yOff), z.AsSpan(zOff));
    }

    public static void XorBothTo(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
    {
        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..16]);
            var Y = MemoryMarshal.AsBytes(y[..16]);
            var Z = MemoryMarshal.AsBytes(z[..16]);

            var X0 = MemoryMarshal.Read<Vector256<byte>>(X[0x00..0x20]);
            var X1 = MemoryMarshal.Read<Vector256<byte>>(X[0x20..0x40]);

            var Y0 = MemoryMarshal.Read<Vector256<byte>>(Y[0x00..0x20]);
            var Y1 = MemoryMarshal.Read<Vector256<byte>>(Y[0x20..0x40]);

            var Z0 = MemoryMarshal.Read<Vector256<byte>>(Z[0x00..0x20]);
            var Z1 = MemoryMarshal.Read<Vector256<byte>>(Z[0x20..0x40]);

            Z0 = Avx2.Xor(Z0, Avx2.Xor(X0, Y0));
            Z1 = Avx2.Xor(Z1, Avx2.Xor(X1, Y1));

            MemoryMarshal.Write(Z[0x00..0x20], in Z0);
            MemoryMarshal.Write(Z[0x20..0x40], in Z1);
            return;
        }

        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..16]);
            var Y = MemoryMarshal.AsBytes(y[..16]);
            var Z = MemoryMarshal.AsBytes(z[..16]);

            var X0 = MemoryMarshal.Read<Vector128<byte>>(X[0x00..0x10]);
            var X1 = MemoryMarshal.Read<Vector128<byte>>(X[0x10..0x20]);
            var X2 = MemoryMarshal.Read<Vector128<byte>>(X[0x20..0x30]);
            var X3 = MemoryMarshal.Read<Vector128<byte>>(X[0x30..0x40]);

            var Y0 = MemoryMarshal.Read<Vector128<byte>>(Y[0x00..0x10]);
            var Y1 = MemoryMarshal.Read<Vector128<byte>>(Y[0x10..0x20]);
            var Y2 = MemoryMarshal.Read<Vector128<byte>>(Y[0x20..0x30]);
            var Y3 = MemoryMarshal.Read<Vector128<byte>>(Y[0x30..0x40]);

            var Z0 = MemoryMarshal.Read<Vector128<byte>>(Z[0x00..0x10]);
            var Z1 = MemoryMarshal.Read<Vector128<byte>>(Z[0x10..0x20]);
            var Z2 = MemoryMarshal.Read<Vector128<byte>>(Z[0x20..0x30]);
            var Z3 = MemoryMarshal.Read<Vector128<byte>>(Z[0x30..0x40]);

            Z0 = Sse2.Xor(Z0, Sse2.Xor(X0, Y0));
            Z1 = Sse2.Xor(Z1, Sse2.Xor(X1, Y1));
            Z2 = Sse2.Xor(Z2, Sse2.Xor(X2, Y2));
            Z3 = Sse2.Xor(Z3, Sse2.Xor(X3, Y3));

            MemoryMarshal.Write(Z[0x00..0x10], in Z0);
            MemoryMarshal.Write(Z[0x10..0x20], in Z1);
            MemoryMarshal.Write(Z[0x20..0x30], in Z2);
            MemoryMarshal.Write(Z[0x30..0x40], in Z3);
            return;
        }

        for (int i = 0; i < 16; i += 4)
        {
            z[i + 0] ^= x[i + 0] ^ y[i + 0];
            z[i + 1] ^= x[i + 1] ^ y[i + 1];
            z[i + 2] ^= x[i + 2] ^ y[i + 2];
            z[i + 3] ^= x[i + 3] ^ y[i + 3];
        }
    }

    public static void XorBothTo64(ulong[] x, ulong[] y, ulong[] z)
    {
        XorBothTo64(x.AsSpan(), y.AsSpan(), z.AsSpan());
    }

    public static void XorBothTo64(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
    {
        XorBothTo64(x.AsSpan(xOff), y.AsSpan(yOff), z.AsSpan(zOff));
    }

    public static void XorBothTo64(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> z)
    {
        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..8]);
            var Y = MemoryMarshal.AsBytes(y[..8]);
            var Z = MemoryMarshal.AsBytes(z[..8]);

            var X0 = MemoryMarshal.Read<Vector256<byte>>(X[0x00..0x20]);
            var X1 = MemoryMarshal.Read<Vector256<byte>>(X[0x20..0x40]);

            var Y0 = MemoryMarshal.Read<Vector256<byte>>(Y[0x00..0x20]);
            var Y1 = MemoryMarshal.Read<Vector256<byte>>(Y[0x20..0x40]);

            var Z0 = MemoryMarshal.Read<Vector256<byte>>(Z[0x00..0x20]);
            var Z1 = MemoryMarshal.Read<Vector256<byte>>(Z[0x20..0x40]);

            Z0 = Avx2.Xor(Z0, Avx2.Xor(X0, Y0));
            Z1 = Avx2.Xor(Z1, Avx2.Xor(X1, Y1));

            MemoryMarshal.Write(Z[0x00..0x20], in Z0);
            MemoryMarshal.Write(Z[0x20..0x40], in Z1);
            return;
        }

        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..8]);
            var Y = MemoryMarshal.AsBytes(y[..8]);
            var Z = MemoryMarshal.AsBytes(z[..8]);

            var X0 = MemoryMarshal.Read<Vector128<byte>>(X[0x00..0x10]);
            var X1 = MemoryMarshal.Read<Vector128<byte>>(X[0x10..0x20]);
            var X2 = MemoryMarshal.Read<Vector128<byte>>(X[0x20..0x30]);
            var X3 = MemoryMarshal.Read<Vector128<byte>>(X[0x30..0x40]);

            var Y0 = MemoryMarshal.Read<Vector128<byte>>(Y[0x00..0x10]);
            var Y1 = MemoryMarshal.Read<Vector128<byte>>(Y[0x10..0x20]);
            var Y2 = MemoryMarshal.Read<Vector128<byte>>(Y[0x20..0x30]);
            var Y3 = MemoryMarshal.Read<Vector128<byte>>(Y[0x30..0x40]);

            var Z0 = MemoryMarshal.Read<Vector128<byte>>(Z[0x00..0x10]);
            var Z1 = MemoryMarshal.Read<Vector128<byte>>(Z[0x10..0x20]);
            var Z2 = MemoryMarshal.Read<Vector128<byte>>(Z[0x20..0x30]);
            var Z3 = MemoryMarshal.Read<Vector128<byte>>(Z[0x30..0x40]);

            Z0 = Sse2.Xor(Z0, Sse2.Xor(X0, Y0));
            Z1 = Sse2.Xor(Z1, Sse2.Xor(X1, Y1));
            Z2 = Sse2.Xor(Z2, Sse2.Xor(X2, Y2));
            Z3 = Sse2.Xor(Z3, Sse2.Xor(X3, Y3));

            MemoryMarshal.Write(Z[0x00..0x10], in Z0);
            MemoryMarshal.Write(Z[0x10..0x20], in Z1);
            MemoryMarshal.Write(Z[0x20..0x30], in Z2);
            MemoryMarshal.Write(Z[0x30..0x40], in Z3);
            return;
        }

        for (int i = 0; i < 8; i += 4)
        {
            z[i + 0] ^= x[i + 0] ^ y[i + 0];
            z[i + 1] ^= x[i + 1] ^ y[i + 1];
            z[i + 2] ^= x[i + 2] ^ y[i + 2];
            z[i + 3] ^= x[i + 3] ^ y[i + 3];
        }
    }

    public static void XorTo(uint[] x, uint[] z)
    {
        XorTo(x.AsSpan(), z.AsSpan());
    }

    public static void XorTo(uint[] x, int xOff, uint[] z, int zOff)
    {
        XorTo(x.AsSpan(xOff), z.AsSpan(zOff));
    }

    public static void XorTo(ReadOnlySpan<uint> x, Span<uint> z)
    {
        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..16]);
            var Z = MemoryMarshal.AsBytes(z[..16]);

            var X0 = MemoryMarshal.Read<Vector256<byte>>(X[0x00..0x20]);
            var X1 = MemoryMarshal.Read<Vector256<byte>>(X[0x20..0x40]);

            var Z0 = MemoryMarshal.Read<Vector256<byte>>(Z[0x00..0x20]);
            var Z1 = MemoryMarshal.Read<Vector256<byte>>(Z[0x20..0x40]);

            Z0 = Avx2.Xor(Z0, X0);
            Z1 = Avx2.Xor(Z1, X1);

            MemoryMarshal.Write(Z[0x00..0x20], in Z0);
            MemoryMarshal.Write(Z[0x20..0x40], in Z1);
            return;
        }

        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..16]);
            var Z = MemoryMarshal.AsBytes(z[..16]);

            var X0 = MemoryMarshal.Read<Vector128<byte>>(X[0x00..0x10]);
            var X1 = MemoryMarshal.Read<Vector128<byte>>(X[0x10..0x20]);
            var X2 = MemoryMarshal.Read<Vector128<byte>>(X[0x20..0x30]);
            var X3 = MemoryMarshal.Read<Vector128<byte>>(X[0x30..0x40]);

            var Z0 = MemoryMarshal.Read<Vector128<byte>>(Z[0x00..0x10]);
            var Z1 = MemoryMarshal.Read<Vector128<byte>>(Z[0x10..0x20]);
            var Z2 = MemoryMarshal.Read<Vector128<byte>>(Z[0x20..0x30]);
            var Z3 = MemoryMarshal.Read<Vector128<byte>>(Z[0x30..0x40]);

            Z0 = Sse2.Xor(Z0, X0);
            Z1 = Sse2.Xor(Z1, X1);
            Z2 = Sse2.Xor(Z2, X2);
            Z3 = Sse2.Xor(Z3, X3);

            MemoryMarshal.Write(Z[0x00..0x10], in Z0);
            MemoryMarshal.Write(Z[0x10..0x20], in Z1);
            MemoryMarshal.Write(Z[0x20..0x30], in Z2);
            MemoryMarshal.Write(Z[0x30..0x40], in Z3);
            return;
        }

        for (int i = 0; i < 16; i += 4)
        {
            z[i + 0] ^= x[i + 0];
            z[i + 1] ^= x[i + 1];
            z[i + 2] ^= x[i + 2];
            z[i + 3] ^= x[i + 3];
        }
    }

    public static void XorTo64(ulong[] x, ulong[] z)
    {
        XorTo64(x.AsSpan(), z.AsSpan());
    }

    public static void XorTo64(ulong[] x, int xOff, ulong[] z, int zOff)
    {
        XorTo64(x.AsSpan(xOff), z.AsSpan(zOff));
    }

    public static void XorTo64(ReadOnlySpan<ulong> x, Span<ulong> z)
    {
        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..8]);
            var Z = MemoryMarshal.AsBytes(z[..8]);

            var X0 = MemoryMarshal.Read<Vector256<byte>>(X[0x00..0x20]);
            var X1 = MemoryMarshal.Read<Vector256<byte>>(X[0x20..0x40]);

            var Y0 = MemoryMarshal.Read<Vector256<byte>>(Z[0x00..0x20]);
            var Y1 = MemoryMarshal.Read<Vector256<byte>>(Z[0x20..0x40]);

            var Z0 = Avx2.Xor(X0, Y0);
            var Z1 = Avx2.Xor(X1, Y1);

            MemoryMarshal.Write(Z[0x00..0x20], in Z0);
            MemoryMarshal.Write(Z[0x20..0x40], in Z1);
            return;
        }

        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var X = MemoryMarshal.AsBytes(x[..8]);
            var Z = MemoryMarshal.AsBytes(z[..8]);

            var X0 = MemoryMarshal.Read<Vector128<byte>>(X[0x00..0x10]);
            var X1 = MemoryMarshal.Read<Vector128<byte>>(X[0x10..0x20]);
            var X2 = MemoryMarshal.Read<Vector128<byte>>(X[0x20..0x30]);
            var X3 = MemoryMarshal.Read<Vector128<byte>>(X[0x30..0x40]);

            var Y0 = MemoryMarshal.Read<Vector128<byte>>(Z[0x00..0x10]);
            var Y1 = MemoryMarshal.Read<Vector128<byte>>(Z[0x10..0x20]);
            var Y2 = MemoryMarshal.Read<Vector128<byte>>(Z[0x20..0x30]);
            var Y3 = MemoryMarshal.Read<Vector128<byte>>(Z[0x30..0x40]);

            var Z0 = Sse2.Xor(X0, Y0);
            var Z1 = Sse2.Xor(X1, Y1);
            var Z2 = Sse2.Xor(X2, Y2);
            var Z3 = Sse2.Xor(X3, Y3);

            MemoryMarshal.Write(Z[0x00..0x10], in Z0);
            MemoryMarshal.Write(Z[0x10..0x20], in Z1);
            MemoryMarshal.Write(Z[0x20..0x30], in Z2);
            MemoryMarshal.Write(Z[0x30..0x40], in Z3);
            return;
        }

        for (int i = 0; i < 8; i += 4)
        {
            z[i + 0] ^= x[i + 0];
            z[i + 1] ^= x[i + 1];
            z[i + 2] ^= x[i + 2];
            z[i + 3] ^= x[i + 3];
        }
    }

    public static void XorToEachOther(uint[] u, uint[] v)
    {
        XorToEachOther(u.AsSpan(), v.AsSpan());
    }

    public static void XorToEachOther(uint[] u, int uOff, uint[] v, int vOff)
    {
        XorToEachOther(u.AsSpan(uOff), v.AsSpan(vOff));
    }

    public static void XorToEachOther(Span<uint> u, Span<uint> v)
    {
        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var U = MemoryMarshal.AsBytes(u[..16]);
            var V = MemoryMarshal.AsBytes(v[..16]);

            var U0 = MemoryMarshal.Read<Vector256<byte>>(U[0x00..0x20]);
            var U1 = MemoryMarshal.Read<Vector256<byte>>(U[0x20..0x40]);

            var V0 = MemoryMarshal.Read<Vector256<byte>>(V[0x00..0x20]);
            var V1 = MemoryMarshal.Read<Vector256<byte>>(V[0x20..0x40]);

            var T0 = Avx2.Xor(U0, V0);
            var T1 = Avx2.Xor(U1, V1);

            MemoryMarshal.Write(U[0x00..0x20], in T0);
            MemoryMarshal.Write(U[0x20..0x40], in T1);
            MemoryMarshal.Write(V[0x00..0x20], in T0);
            MemoryMarshal.Write(V[0x20..0x40], in T1);
            return;
        }

        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var U = MemoryMarshal.AsBytes(u[..16]);
            var V = MemoryMarshal.AsBytes(v[..16]);

            var U0 = MemoryMarshal.Read<Vector128<byte>>(U[0x00..0x10]);
            var U1 = MemoryMarshal.Read<Vector128<byte>>(U[0x10..0x20]);
            var U2 = MemoryMarshal.Read<Vector128<byte>>(U[0x20..0x30]);
            var U3 = MemoryMarshal.Read<Vector128<byte>>(U[0x30..0x40]);

            var V0 = MemoryMarshal.Read<Vector128<byte>>(V[0x00..0x10]);
            var V1 = MemoryMarshal.Read<Vector128<byte>>(V[0x10..0x20]);
            var V2 = MemoryMarshal.Read<Vector128<byte>>(V[0x20..0x30]);
            var V3 = MemoryMarshal.Read<Vector128<byte>>(V[0x30..0x40]);

            var T0 = Sse2.Xor(U0, V0);
            var T1 = Sse2.Xor(U1, V1);
            var T2 = Sse2.Xor(U2, V2);
            var T3 = Sse2.Xor(U3, V3);

            MemoryMarshal.Write(U[0x00..0x10], in T0);
            MemoryMarshal.Write(V[0x00..0x10], in T0);
            MemoryMarshal.Write(U[0x10..0x20], in T1);
            MemoryMarshal.Write(V[0x10..0x20], in T1);
            MemoryMarshal.Write(U[0x20..0x30], in T2);
            MemoryMarshal.Write(V[0x20..0x30], in T2);
            MemoryMarshal.Write(U[0x30..0x40], in T3);
            MemoryMarshal.Write(V[0x30..0x40], in T3);
            return;
        }

        for (int i = 0; i < 16; ++i)
        {
            uint t = u[i] ^ v[i];
            u[i] = t;
            v[i] = t;
        }
    }

    public static void XorToEachOther64(ulong[] u, ulong[] v)
    {
        XorToEachOther64(u.AsSpan(), v.AsSpan());
    }

    public static void XorToEachOther64(ulong[] u, int uOff, ulong[] v, int vOff)
    {
        XorToEachOther64(u.AsSpan(uOff), v.AsSpan(vOff));
    }

    public static void XorToEachOther64(Span<ulong> u, Span<ulong> v)
    {
        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var U = MemoryMarshal.AsBytes(u[..8]);
            var V = MemoryMarshal.AsBytes(v[..8]);

            var U0 = MemoryMarshal.Read<Vector256<byte>>(U[0x00..0x20]);
            var U1 = MemoryMarshal.Read<Vector256<byte>>(U[0x20..0x40]);

            var V0 = MemoryMarshal.Read<Vector256<byte>>(V[0x00..0x20]);
            var V1 = MemoryMarshal.Read<Vector256<byte>>(V[0x20..0x40]);

            var T0 = Avx2.Xor(U0, V0);
            var T1 = Avx2.Xor(U1, V1);

            MemoryMarshal.Write(U[0x00..0x20], in T0);
            MemoryMarshal.Write(U[0x20..0x40], in T1);
            MemoryMarshal.Write(V[0x00..0x20], in T0);
            MemoryMarshal.Write(V[0x20..0x40], in T1);
            return;
        }

        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var U = MemoryMarshal.AsBytes(u[..8]);
            var V = MemoryMarshal.AsBytes(v[..8]);

            var U0 = MemoryMarshal.Read<Vector128<byte>>(U[0x00..0x10]);
            var U1 = MemoryMarshal.Read<Vector128<byte>>(U[0x10..0x20]);
            var U2 = MemoryMarshal.Read<Vector128<byte>>(U[0x20..0x30]);
            var U3 = MemoryMarshal.Read<Vector128<byte>>(U[0x30..0x40]);

            var V0 = MemoryMarshal.Read<Vector128<byte>>(V[0x00..0x10]);
            var V1 = MemoryMarshal.Read<Vector128<byte>>(V[0x10..0x20]);
            var V2 = MemoryMarshal.Read<Vector128<byte>>(V[0x20..0x30]);
            var V3 = MemoryMarshal.Read<Vector128<byte>>(V[0x30..0x40]);

            var T0 = Sse2.Xor(U0, V0);
            var T1 = Sse2.Xor(U1, V1);
            var T2 = Sse2.Xor(U2, V2);
            var T3 = Sse2.Xor(U3, V3);

            MemoryMarshal.Write(U[0x00..0x10], in T0);
            MemoryMarshal.Write(V[0x00..0x10], in T0);
            MemoryMarshal.Write(U[0x10..0x20], in T1);
            MemoryMarshal.Write(V[0x10..0x20], in T1);
            MemoryMarshal.Write(U[0x20..0x30], in T2);
            MemoryMarshal.Write(V[0x20..0x30], in T2);
            MemoryMarshal.Write(U[0x30..0x40], in T3);
            MemoryMarshal.Write(V[0x30..0x40], in T3);
            return;
        }

        for (int i = 0; i < 8; ++i)
        {
            ulong t = u[i] ^ v[i];
            u[i] = t;
            v[i] = t;
        }
    }

    public static void Zero(uint[] z)
    {
        Zero(z.AsSpan());
    }

    public static void Zero(uint[] z, int zOff)
    {
        Zero(z.AsSpan(zOff));
    }

    public static void Zero(Span<uint> z)
    {
        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var Z = MemoryMarshal.AsBytes(z[..16]);

            var Z_ = Vector256<byte>.Zero;

            MemoryMarshal.Write(Z[0x00..0x20], in Z_);
            MemoryMarshal.Write(Z[0x20..0x40], in Z_);
            return;
        }

        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var Z = MemoryMarshal.AsBytes(z[..16]);

            var Z_ = Vector128<byte>.Zero;

            MemoryMarshal.Write(Z[0x00..0x10], in Z_);
            MemoryMarshal.Write(Z[0x10..0x20], in Z_);
            MemoryMarshal.Write(Z[0x20..0x30], in Z_);
            MemoryMarshal.Write(Z[0x30..0x40], in Z_);
            return;
        }

        z[..16].Fill(0U);
    }

    public static void Zero64(ulong[] z)
    {
        Zero64(z.AsSpan());
    }

    public static void Zero64(ulong[] z, int zOff)
    {
        Zero64(z.AsSpan(zOff));
    }

    public static void Zero64(Span<ulong> z)
    {
        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var Z = MemoryMarshal.AsBytes(z[..8]);

            var Z_ = Vector256<byte>.Zero;

            MemoryMarshal.Write(Z[0x00..0x20], in Z_);
            MemoryMarshal.Write(Z[0x20..0x40], in Z_);
            return;
        }

        if (CodeBrix.Cryptography.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
            CodeBrix.Cryptography.Runtime.Intrinsics.Vector.IsPacked)
        {
            var Z = MemoryMarshal.AsBytes(z[..8]);

            var Z_ = Vector128<byte>.Zero;

            MemoryMarshal.Write(Z[0x00..0x10], in Z_);
            MemoryMarshal.Write(Z[0x10..0x20], in Z_);
            MemoryMarshal.Write(Z[0x20..0x30], in Z_);
            MemoryMarshal.Write(Z[0x30..0x40], in Z_);
            return;
        }

        z[..8].Fill(0UL);
    }
}
