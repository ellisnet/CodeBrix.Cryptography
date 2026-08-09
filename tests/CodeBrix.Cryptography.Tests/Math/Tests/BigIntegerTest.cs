using System;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Encoders;
using Xunit;

namespace CodeBrix.Cryptography.Math.Tests; //was previously: Org.BouncyCastle.Math.Tests;

public class BigIntegerTest
{
    private static readonly Random random = new Random();

    [Fact]
    public void MonoBug81857()
    {
        BigInteger b = new BigInteger("18446744073709551616");
        BigInteger mod = new BigInteger("48112959837082048697");
        BigInteger expected = new BigInteger("4970597831480284165");

        BigInteger byModMultiply = b.ModMultiply(b, mod);
        Assert.Equal(expected, byModMultiply);

        BigInteger byModSquare = b.ModSquare(mod);
        Assert.Equal(expected, byModSquare);

        BigInteger byMultiply = b.Multiply(b).Mod(mod);
        Assert.Equal(expected, byMultiply);

        BigInteger bySquare = b.Square().Mod(mod);
        Assert.Equal(expected, bySquare);

        BigInteger byModPow = b.ModPow(BigInteger.Two, mod);
        Assert.Equal(expected, byModPow);
    }

    [Fact]
    public void TestAbs()
    {
        Assert.Equal(Zero, Zero.Abs());

        Assert.Equal(One, One.Abs());
        Assert.Equal(One, MinusOne.Abs());

        Assert.Equal(Two, Two.Abs());
        Assert.Equal(Two, MinusTwo.Abs());
    }

    [Fact]
    public void TestAdd()
    {
        for (int i = -16; i <= 16; ++i)
        {
            for (int j = -16; j <= 16; ++j)
            {
                Assert.Equal(Val(i + j), Val(i).Add(Val(j)));
            }
        }
    }

    [Fact]
    public void TestAnd()
    {
        for (int i = -16; i <= 16; ++i)
        {
            for (int j = -16; j <= 16; ++j)
            {
                Assert.Equal(Val(i & j), Val(i).And(Val(j)));
            }
        }
    }

    [Fact]
    public void TestAndNot()
    {
        for (int i = -16; i <= 16; ++i)
        {
            for (int j = -16; j <= 16; ++j)
            {
                Assert.Equal(Val(i & ~j), Val(i).AndNot(Val(j)));
            }
        }
    }

    [Fact]
    public void TestBitCount()
    {
        Assert.Equal(0, Zero.BitCount);
        Assert.Equal(1, One.BitCount);
        Assert.Equal(0, MinusOne.BitCount);
        Assert.Equal(1, Two.BitCount);
        Assert.Equal(1, MinusTwo.BitCount);

        for (int i = 0; i < 100; ++i)
        {
            BigInteger pow2 = One.ShiftLeft(i);

            Assert.Equal(1, pow2.BitCount);
            Assert.Equal(i, pow2.Negate().BitCount);
        }

        for (int i = 0; i < 10; ++i)
        {
            BigInteger test = new BigInteger(128, 0, random);
            int bitCount = 0;

            for (int bit = 0; bit < test.BitLength; ++bit)
            {
                if (test.TestBit(bit))
                {
                    ++bitCount;
                }
            }

            Assert.Equal(bitCount, test.BitCount);
        }
    }

    [Fact]
    public void TestBitLength()
    {
        Assert.Equal(0, Zero.BitLength);
        Assert.Equal(1, One.BitLength);
        Assert.Equal(0, MinusOne.BitLength);
        Assert.Equal(2, Two.BitLength);
        Assert.Equal(1, MinusTwo.BitLength);

        for (int i = 0; i < 100; ++i)
        {
            int bit = i + random.Next(64);
            BigInteger odd = new BigInteger(bit, random).SetBit(bit + 1).SetBit(0);
            BigInteger pow2 = One.ShiftLeft(bit);

            Assert.Equal(bit + 2, odd.BitLength);
            Assert.Equal(bit + 2, odd.Negate().BitLength);
            Assert.Equal(bit + 1, pow2.BitLength);
            Assert.Equal(bit, pow2.Negate().BitLength);
        }
    }

    [Fact]
    public void TestClearBit()
    {
        Assert.Equal(Zero, Zero.ClearBit(0));
        Assert.Equal(Zero, One.ClearBit(0));
        Assert.Equal(Two, Two.ClearBit(0));

        Assert.Equal(Zero, Zero.ClearBit(1));
        Assert.Equal(One, One.ClearBit(1));
        Assert.Equal(Zero, Two.ClearBit(1));

        // TODO Tests for clearing bits in negative numbers

        // TODO Tests for clearing extended bits

        for (int i = 0; i < 10; ++i)
        {
            BigInteger n = new BigInteger(128, random);

            for (int j = 0; j < 10; ++j)
            {
                int pos = random.Next(128);
                BigInteger m = n.ClearBit(pos);
                bool test = m.ShiftRight(pos).Remainder(Two).Equals(One);

                Assert.False(test);
            }
        }

        for (int i = 0; i < 100; ++i)
        {
            BigInteger pow2 = One.ShiftLeft(i);
            BigInteger minusPow2 = pow2.Negate();

            Assert.Equal(Zero, pow2.ClearBit(i));
            Assert.Equal(minusPow2.ShiftLeft(1), minusPow2.ClearBit(i));

            BigInteger bigI = Val(i);
            BigInteger negI = bigI.Negate();

            for (int j = 0; j < 10; ++j)
            {
                string data = "i=" + i + ", j=" + j;
                Assert.Equal(bigI.AndNot(One.ShiftLeft(j)), bigI.ClearBit(j));
                Assert.Equal(negI.AndNot(One.ShiftLeft(j)), negI.ClearBit(j));
            }
        }
    }

    [Fact]
    public void TestCompareTo()
    {
        Assert.Equal(0, MinusTwo.CompareTo(MinusTwo));
        Assert.Equal(-1, MinusTwo.CompareTo(MinusOne));
        Assert.Equal(-1, MinusTwo.CompareTo(Zero));
        Assert.Equal(-1, MinusTwo.CompareTo(One));
        Assert.Equal(-1, MinusTwo.CompareTo(Two));

        Assert.Equal(1, MinusOne.CompareTo(MinusTwo));
        Assert.Equal(0, MinusOne.CompareTo(MinusOne));
        Assert.Equal(-1, MinusOne.CompareTo(Zero));
        Assert.Equal(-1, MinusOne.CompareTo(One));
        Assert.Equal(-1, MinusOne.CompareTo(Two));

        Assert.Equal(1, Zero.CompareTo(MinusTwo));
        Assert.Equal(1, Zero.CompareTo(MinusOne));
        Assert.Equal(0, Zero.CompareTo(Zero));
        Assert.Equal(-1, Zero.CompareTo(One));
        Assert.Equal(-1, Zero.CompareTo(Two));

        Assert.Equal(1, One.CompareTo(MinusTwo));
        Assert.Equal(1, One.CompareTo(MinusOne));
        Assert.Equal(1, One.CompareTo(Zero));
        Assert.Equal(0, One.CompareTo(One));
        Assert.Equal(-1, One.CompareTo(Two));

        Assert.Equal(1, Two.CompareTo(MinusTwo));
        Assert.Equal(1, Two.CompareTo(MinusOne));
        Assert.Equal(1, Two.CompareTo(Zero));
        Assert.Equal(1, Two.CompareTo(One));
        Assert.Equal(0, Two.CompareTo(Two));
    }

    [Fact]
    public void TestConstructors()
    {
        ImplTestBytesConstructors(0, new byte[]{ 0x00 });
        ImplTestBytesConstructors(0, new byte[]{ 0x00, 0x00 });
        ImplTestBytesConstructors(-1, new byte[]{ 0xFF });
        ImplTestBytesConstructors(-1, new byte[]{ 0xFF, 0xFF });
        ImplTestBytesConstructors(-1 << 7, new byte[]{ 0x80 });
        ImplTestBytesConstructors(-1 << 7, new byte[]{ 0xFF, 0x80 });
        ImplTestBytesConstructors(-1 << 8, new byte[]{ 0xFF, 0x00 });
        ImplTestBytesConstructors(-1 << 8, new byte[]{ 0xFF, 0xFF, 0x00 });
        ImplTestBytesConstructors(-1 << 15, new byte[]{ 0x80, 0x00 });
        ImplTestBytesConstructors(-1 << 15, new byte[]{ 0xFF, 0x80, 0x00 });
        ImplTestBytesConstructors(-1 << 16, new byte[]{ 0xFF, 0x00, 0x00 });
        ImplTestBytesConstructors(-1 << 16, new byte[]{ 0xFF, 0xFF, 0x00, 0x00 });

        for (int i = 0; i < 10; ++i)
        {
            Assert.True(new BigInteger(i + 3, 0, random).TestBit(0));
        }

        // TODO Other constructors
    }

    [Fact]
    public void TestDivide()
    {
        for (int i = -16; i <= 16; ++i)
        {
            try
            {
                Val(i).Divide(Zero);
                Assert.Fail("expected ArithmeticException");
            }
            catch (ArithmeticException) {}
        }

        int product = 1 * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9;
        int productPlus = product + 1;

        BigInteger bigProduct = Val(product);
        BigInteger bigProductPlus = Val(productPlus);

        for (int divisor = 1; divisor < 10; ++divisor)
        {
            // Exact division
            BigInteger expected = Val(product / divisor);

            Assert.Equal(expected, bigProduct.Divide(Val(divisor)));
            Assert.Equal(expected.Negate(), bigProduct.Negate().Divide(Val(divisor)));
            Assert.Equal(expected.Negate(), bigProduct.Divide(Val(divisor).Negate()));
            Assert.Equal(expected, bigProduct.Negate().Divide(Val(divisor).Negate()));

            expected = Val((product + 1)/divisor);

            Assert.Equal(expected, bigProductPlus.Divide(Val(divisor)));
            Assert.Equal(expected.Negate(), bigProductPlus.Negate().Divide(Val(divisor)));
            Assert.Equal(expected.Negate(), bigProductPlus.Divide(Val(divisor).Negate()));
            Assert.Equal(expected, bigProductPlus.Negate().Divide(Val(divisor).Negate()));
        }

        for (int rep = 0; rep < 10; ++rep)
        {
            BigInteger a = new BigInteger(100 - rep, 0, random);
            BigInteger b = new BigInteger(100 + rep, 0, random);
            BigInteger c = new BigInteger(10 + rep, 0, random);
            BigInteger d = a.Multiply(b).Add(c);
            BigInteger e = d.Divide(a);

            Assert.Equal(b, e);
        }

        // Special tests for power of two since uses different code path internally
        for (int i = 0; i < 100; ++i)
        {
            int shift = random.Next(64);
            BigInteger a = One.ShiftLeft(shift);
            BigInteger b = new BigInteger(64 + random.Next(64), random);
            BigInteger bShift = b.ShiftRight(shift);

            string data = "shift=" + shift +", b=" + b.ToString(16);

            Assert.Equal(bShift, b.Divide(a));
            Assert.Equal(bShift.Negate(), b.Divide(a.Negate()));
            Assert.Equal(bShift.Negate(), b.Negate().Divide(a));
            Assert.Equal(bShift, b.Negate().Divide(a.Negate()));
        }

        // Regression
        {
            int shift = 63;
            BigInteger a = One.ShiftLeft(shift);
            BigInteger b = new BigInteger(1, Hex.Decode("2504b470dc188499"));
            BigInteger bShift = b.ShiftRight(shift);

            string data = "shift=" + shift +", b=" + b.ToString(16);

            Assert.Equal(bShift, b.Divide(a));
            Assert.Equal(bShift.Negate(), b.Divide(a.Negate()));
//				Assert.Equal(bShift.Negate(), b.Negate().Divide(a));
            Assert.Equal(bShift, b.Negate().Divide(a.Negate()));
        }
    }

    [Fact]
    public void TestDivideAndRemainder()
    {
        // TODO More basic tests

        BigInteger n = new BigInteger(48, random);
        BigInteger[] qr = n.DivideAndRemainder(n);
        Assert.Equal(One, qr[0]);
        Assert.Equal(Zero, qr[1]);
        qr = n.DivideAndRemainder(One);
        Assert.Equal(n, qr[0]);
        Assert.Equal(Zero, qr[1]);

        for (int rep = 0; rep < 10; ++rep)
        {
            BigInteger a = new BigInteger(100 - rep, 0, random);
            BigInteger b = new BigInteger(100 + rep, 0, random);
            BigInteger c = new BigInteger(10 + rep, 0, random);
            BigInteger d = a.Multiply(b).Add(c);
            BigInteger[] es = d.DivideAndRemainder(a);

            Assert.Equal(b, es[0]);
            Assert.Equal(c, es[1]);
        }

        // Special tests for power of two since uses different code path internally
        for (int i = 0; i < 100; ++i)
        {
            int shift = random.Next(64);
            BigInteger a = One.ShiftLeft(shift);
            BigInteger b = new BigInteger(64 + random.Next(64), random);
            BigInteger bShift = b.ShiftRight(shift);
            BigInteger bMod = b.And(a.Subtract(One));

            string data = "shift=" + shift +", b=" + b.ToString(16);

            qr = b.DivideAndRemainder(a);
            Assert.Equal(bShift, qr[0]);
            Assert.Equal(bMod, qr[1]);

            qr = b.DivideAndRemainder(a.Negate());
            Assert.Equal(bShift.Negate(), qr[0]);
            Assert.Equal(bMod, qr[1]);

            qr = b.Negate().DivideAndRemainder(a);
            Assert.Equal(bShift.Negate(), qr[0]);
            Assert.Equal(bMod.Negate(), qr[1]);

            qr = b.Negate().DivideAndRemainder(a.Negate());
            Assert.Equal(bShift, qr[0]);
            Assert.Equal(bMod.Negate(), qr[1]);
        }
    }

    [Fact]
    public void TestFlipBit()
    {
        for (int i = 0; i < 10; ++i)
        {
            BigInteger a = new BigInteger(128, 0, random);
            BigInteger b = a;

            for (int x = 0; x < 100; ++x)
            {
                // Note: Intentionally greater than initial size
                int pos = random.Next(256);

                a = a.FlipBit(pos);
                b = b.TestBit(pos) ? b.ClearBit(pos) : b.SetBit(pos);
            }

            Assert.Equal(a, b);
        }

        for (int i = 0; i < 100; ++i)
        {
            BigInteger pow2 = One.ShiftLeft(i);
            BigInteger minusPow2 = pow2.Negate();

            Assert.Equal(Zero, pow2.FlipBit(i));
            Assert.Equal(minusPow2.ShiftLeft(1), minusPow2.FlipBit(i));

            BigInteger bigI = Val(i);
            BigInteger negI = bigI.Negate();

            for (int j = 0; j < 10; ++j)
            {
                string data = "i=" + i + ", j=" + j;
                Assert.Equal(bigI.Xor(One.ShiftLeft(j)), bigI.FlipBit(j));
                Assert.Equal(negI.Xor(One.ShiftLeft(j)), negI.FlipBit(j));
            }
        }
    }

    [Fact]
    public void TestGcd()
    {
        for (int i = 0; i < 10; ++i)
        {
            BigInteger fac = new BigInteger(32, random).Add(Two);
            BigInteger p1 = BigInteger.ProbablePrime(63, random);
            BigInteger p2 = BigInteger.ProbablePrime(64, random);

            BigInteger gcd = fac.Multiply(p1).Gcd(fac.Multiply(p2));

            Assert.Equal(fac, gcd);
        }
    }

    [Fact]
    public void TestGetLowestSetBit()
    {
        for (int i = 1; i <= 100; ++i)
        {
            BigInteger test = new BigInteger(i + 1, 0, random).Add(One);
            int bit1 = test.GetLowestSetBit();
            Assert.Equal(test, test.ShiftRight(bit1).ShiftLeft(bit1));
            int bit2 = test.ShiftLeft(i + 1).GetLowestSetBit();
            Assert.Equal(i + 1, bit2 - bit1);
            int bit3 = test.ShiftLeft(3 * i).GetLowestSetBit();
            Assert.Equal(3 * i, bit3 - bit1);
        }
    }

    [Fact]
    public void TestIntValue()
    {
        int[] tests = new int[]{ int.MinValue, -1234, -10, -1, 0, ~0, 1, 10, 5678, int.MaxValue };

        foreach (int test in tests)
        {
            var val = Val(test);
            Assert.Equal(test, val.IntValue);
            Assert.Equal(test, val.IntValueExact);
        }

        // TODO Tests for large numbers
    }

    [Fact]
    public void TestIsProbablePrime()
    {
        Assert.False(Zero.IsProbablePrime(100));
        Assert.False(Zero.IsProbablePrime(100));
        Assert.True(Zero.IsProbablePrime(0));
        Assert.True(Zero.IsProbablePrime(-10));
        Assert.False(MinusOne.IsProbablePrime(100));
        Assert.True(MinusTwo.IsProbablePrime(100));
        Assert.True(Val(-17).IsProbablePrime(100));
        Assert.True(Val(67).IsProbablePrime(100));
        Assert.True(Val(773).IsProbablePrime(100));

        foreach (int p in FirstPrimes)
        {
            Assert.True(Val(p).IsProbablePrime(100));
            Assert.True(Val(-p).IsProbablePrime(100));
        }

        foreach (int c in NonPrimes)
        {
            Assert.False(Val(c).IsProbablePrime(100));
            Assert.False(Val(-c).IsProbablePrime(100));
        }

        foreach (int e in MersennePrimeExponents)
        {
            Assert.True(Mersenne(e).IsProbablePrime(100));
            Assert.True(Mersenne(e).Negate().IsProbablePrime(100));
        }

        foreach (int e in NonPrimeExponents)
        {
            Assert.False(Mersenne(e).IsProbablePrime(100));
            Assert.False(Mersenne(e).Negate().IsProbablePrime(100));
        }

        // TODO Other examples of 'tricky' values?
    }

    [Fact]
    public void TestLongValue()
    {
        long[] tests = { long.MinValue, -1234, -10, -1, 0L, ~0L, 1, 10, 5678, long.MaxValue };

        foreach (long test in tests)
        {
            var val = Val(test);
            Assert.Equal(test, val.LongValue);
            Assert.Equal(test, val.LongValueExact);
        }

        // TODO Tests for large numbers
    }

    [Fact]
    public void TestMax()
    {
        for (int i = -16; i <= 16; ++i)
        {
            for (int j = -16; j <= 16; ++j)
            {
                Assert.Equal(Val(System.Math.Max(i, j)), Val(i).Max(Val(j)));
            }
        }
    }

    [Fact]
    public void TestMin()
    {
        for (int i = -16; i <= 16; ++i)
        {
            for (int j = -16; j <= 16; ++j)
            {
                Assert.Equal(Val(System.Math.Min(i, j)), Val(i).Min(Val(j)));
            }
        }
    }

    [Fact]
    public void TestMod()
    {
        // TODO Basic tests

        for (int rep = 0; rep < 100; ++rep)
        {
            int diff = random.Next(25);
            BigInteger a = new BigInteger(100 - diff, 0, random);
            BigInteger b = new BigInteger(100 + diff, 0, random);
            BigInteger c = new BigInteger(10 + diff, 0, random);

            BigInteger d = a.Multiply(b).Add(c);
            BigInteger e = d.Mod(a);
            Assert.Equal(c, e);

            BigInteger pow2 = One.ShiftLeft(random.Next(128));
            Assert.Equal(b.And(pow2.Subtract(One)), b.Mod(pow2));
        }
    }

    [Fact]
    public void TestModInverse()
    {
        for (int i = 0; i < 10; ++i)
        {
            BigInteger p = BigInteger.ProbablePrime(64, random);
            BigInteger q = new BigInteger(63, random).Add(One);
            BigInteger inv = q.ModInverse(p);
            BigInteger inv2 = inv.ModInverse(p);

            Assert.Equal(q, inv2);
            Assert.Equal(One, q.Multiply(inv).Mod(p));
        }

        // ModInverse a power of 2 for a range of powers
        for (int i = 1; i <= 128; ++i)
        {
            BigInteger m = One.ShiftLeft(i);
            BigInteger d = new BigInteger(i, random).SetBit(0);
            BigInteger x = d.ModInverse(m);
            BigInteger check = x.Multiply(d).Mod(m);

            Assert.Equal(One, check);
        }
    }

    [Fact]
    public void TestModPow()
    {
        try
        {
            Two.ModPow(One, Zero);
            Assert.Fail("expected ArithmeticException");
        }
        catch (ArithmeticException) {}

        Assert.Equal(Zero, Zero.ModPow(Zero, One));
        Assert.Equal(One, Zero.ModPow(Zero, Two));
        Assert.Equal(Zero, Two.ModPow(One, One));
        Assert.Equal(One, Two.ModPow(Zero, Two));

        for (int i = 0; i < 100; ++i)
        {
            BigInteger m = BigInteger.ProbablePrime(10 + i, random);
            BigInteger x = new BigInteger(m.BitLength - 1, random);

            Assert.Equal(x, x.ModPow(m, m));
            if (x.SignValue != 0)
            {
                Assert.Equal(Zero, Zero.ModPow(x, m));
                Assert.Equal(One, x.ModPow(m.Subtract(One), m));
            }

            BigInteger y = new BigInteger(m.BitLength - 1, random);
            BigInteger n = new BigInteger(m.BitLength - 1, random);
            BigInteger n3 = n.ModPow(Three, m);

            BigInteger resX = n.ModPow(x, m);
            BigInteger resY = n.ModPow(y, m);
            BigInteger res = resX.Multiply(resY).Mod(m);
            BigInteger res3 = res.ModPow(Three, m);

            Assert.Equal(res3, n3.ModPow(x.Add(y), m));

            BigInteger a = x.Add(One); // Make sure it's not zero
            BigInteger b = y.Add(One); // Make sure it's not zero

            Assert.Equal(a.ModPow(b, m).ModInverse(m), a.ModPow(b.Negate(), m));
        }
    }

    [Fact]
    public void TestMultiply()
    {
        BigInteger one = BigInteger.One;

        Assert.Equal(one, one.Negate().Multiply(one.Negate()));

        for (int i = 0; i < 100; ++i)
        {
            int aLen = 64 + random.Next(64);
            int bLen = 64 + random.Next(64);

            BigInteger a = new BigInteger(aLen, random).SetBit(aLen);
            BigInteger b = new BigInteger(bLen, random).SetBit(bLen);
            BigInteger c = new BigInteger(32, random);

            BigInteger ab = a.Multiply(b);
            BigInteger bc = b.Multiply(c);

            Assert.Equal(ab.Add(bc), a.Add(c).Multiply(b));
            Assert.Equal(ab.Subtract(bc), a.Subtract(c).Multiply(b));
        }

        // Special tests for power of two since uses different code path internally
        for (int i = 0; i < 100; ++i)
        {
            int shift = random.Next(64);
            BigInteger a = one.ShiftLeft(shift);
            BigInteger b = new BigInteger(64 + random.Next(64), random);
            BigInteger bShift = b.ShiftLeft(shift);

            Assert.Equal(bShift, a.Multiply(b));
            Assert.Equal(bShift.Negate(), a.Multiply(b.Negate()));
            Assert.Equal(bShift.Negate(), a.Negate().Multiply(b));
            Assert.Equal(bShift, a.Negate().Multiply(b.Negate()));

            Assert.Equal(bShift, b.Multiply(a));
            Assert.Equal(bShift.Negate(), b.Multiply(a.Negate()));
            Assert.Equal(bShift.Negate(), b.Negate().Multiply(a));
            Assert.Equal(bShift, b.Negate().Multiply(a.Negate()));
        }
    }

    [Fact]
    public void TestNegate()
    {
        for (int i = -16; i <= 16; ++i)
        {
            Assert.Equal(Val(-i), Val(i).Negate());
        }
    }

    [Fact]
    public void TestNextProbablePrime()
    {
        BigInteger firstPrime = BigInteger.ProbablePrime(32, random);
        BigInteger nextPrime = firstPrime.NextProbablePrime();

        Assert.True(firstPrime.IsProbablePrime(10));
        Assert.True(nextPrime.IsProbablePrime(10));

        BigInteger check = firstPrime.Add(One);

        while (check.CompareTo(nextPrime) < 0)
        {
            Assert.False(check.IsProbablePrime(10));
            check = check.Add(One);
        }
    }

    [Fact]
    public void TestNot()
    {
        for (int i = -16; i <= 16; ++i)
        {
            Assert.Equal(Val(~i), Val(i).Not());
        }
    }

    [Fact]
    public void TestOr()
    {
        for (int i = -16; i <= 16; ++i)
        {
            for (int j = -16; j <= 16; ++j)
            {
                Assert.Equal(Val(i | j), Val(i).Or(Val(j)));
            }
        }
    }

    [Fact]
    public void TestPow()
    {
        Assert.Equal(One, Zero.Pow(0));
        Assert.Equal(Zero, Zero.Pow(123));
        Assert.Equal(One, One.Pow(0));
        Assert.Equal(One, One.Pow(123));

        Assert.Equal(Two.Pow(147), One.ShiftLeft(147));
        Assert.Equal(One.ShiftLeft(7).Pow(11), One.ShiftLeft(77));

        BigInteger n = new BigInteger("1234567890987654321");
        BigInteger result = One;

        for (int i = 0; i < 10; ++i)
        {
            try
            {
                Val(i).Pow(-1);
                Assert.Fail("expected ArithmeticException");
            }
            catch (ArithmeticException) {}

            Assert.Equal(result, n.Pow(i));

            result = result.Multiply(n);
        }
    }

    [Fact]
    public void TestRemainder()
    {
        // TODO Basic tests

        for (int rep = 0; rep < 10; ++rep)
        {
            BigInteger a = new BigInteger(100 - rep, 0, random);
            BigInteger b = new BigInteger(100 + rep, 0, random);
            BigInteger c = new BigInteger(10 + rep, 0, random);
            BigInteger d = a.Multiply(b).Add(c);
            BigInteger e = d.Remainder(a);

            Assert.Equal(c, e);
        }
    }

    [Fact]
    public void TestSetBit()
    {
        Assert.Equal(One, Zero.SetBit(0));
        Assert.Equal(One, One.SetBit(0));
        Assert.Equal(Three, Two.SetBit(0));

        Assert.Equal(Two, Zero.SetBit(1));
        Assert.Equal(Three, One.SetBit(1));
        Assert.Equal(Two, Two.SetBit(1));

        // TODO Tests for setting bits in negative numbers

        // TODO Tests for setting extended bits

        for (int i = 0; i < 10; ++i)
        {
            BigInteger n = new BigInteger(128, random);

            for (int j = 0; j < 10; ++j)
            {
                int pos = random.Next(128);
                BigInteger m = n.SetBit(pos);
                bool test = m.ShiftRight(pos).Remainder(Two).Equals(One);

                Assert.True(test);
            }
        }

        for (int i = 0; i < 100; ++i)
        {
            BigInteger pow2 = One.ShiftLeft(i);
            BigInteger minusPow2 = pow2.Negate();

            Assert.Equal(pow2, pow2.SetBit(i));
            Assert.Equal(minusPow2, minusPow2.SetBit(i));

            BigInteger bigI = Val(i);
            BigInteger negI = bigI.Negate();

            for (int j = 0; j < 10; ++j)
            {
                string data = "i=" + i + ", j=" + j;
                Assert.Equal(bigI.Or(One.ShiftLeft(j)), bigI.SetBit(j));
                Assert.Equal(negI.Or(One.ShiftLeft(j)), negI.SetBit(j));
            }
        }
    }

    [Fact]
    public void TestShiftLeft()
    {
        for (int i = 0; i < 100; ++i)
        {
            int shift = random.Next(128);

            BigInteger a = new BigInteger(128 + i, random).Add(One);
            int aBits = a.BitCount; // Make sure nBits is set
            Assert.True(aBits <= 128 + i + 1);

            BigInteger negA = a.Negate();
            int negABits = negA.BitCount; // Make sure nBits is set
            Assert.True(negABits <= 128 + i + 1);

            BigInteger b = a.ShiftLeft(shift);
            BigInteger c = negA.ShiftLeft(shift);

            Assert.Equal(a.BitCount, b.BitCount);
            Assert.Equal(negA.BitCount + shift, c.BitCount);
            Assert.Equal(a.BitLength + shift, b.BitLength);
            Assert.Equal(negA.BitLength + shift, c.BitLength);

            int j = 0;
            for (; j < shift; ++j)
            {
                Assert.False(b.TestBit(j));
            }

            for (; j < b.BitLength; ++j)
            {
                Assert.Equal(a.TestBit(j - shift), b.TestBit(j));
            }
        }
    }

    [Fact]
    public void TestShiftRight()
    {
        for (int i = 0; i < 10; ++i)
        {
            int shift = random.Next(128);
            BigInteger a = new BigInteger(256 + i, random).SetBit(256 + i);
            BigInteger b = a.ShiftRight(shift);

            Assert.Equal(a.BitLength - shift, b.BitLength);

            for (int j = 0; j < b.BitLength; ++j)
            {
                Assert.Equal(a.TestBit(j + shift), b.TestBit(j));
            }
        }
    }

    [Fact]
    public void TestSignValue()
    {
        for (int i = -16; i <= 16; ++i)
        {
            Assert.Equal(i < 0 ? -1 : i > 0 ? 1 : 0, Val(i).SignValue);
        }
    }

    [Fact]
    public void TestSubtract()
    {
        for (int i = -16; i <= 16; ++i)
        {
            for (int j = -16; j <= 16; ++j)
            {
                Assert.Equal(Val(i - j), Val(i).Subtract(Val(j)));
            }
        }
    }

    [Fact]
    public void TestTestBit()
    {
        for (int i = 0; i < 10; ++i)
        {
            BigInteger n = new BigInteger(128, random);

            Assert.False(n.TestBit(128));
            Assert.True(n.Negate().TestBit(128));

            for (int j = 0; j < 10; ++j)
            {
                int pos = random.Next(128);
                bool test = n.ShiftRight(pos).Remainder(Two).Equals(One);

                Assert.Equal(test, n.TestBit(pos));
            }
        }
    }

    [Fact]
    public void TestToByteArray()
    {
        byte[] z = BigInteger.Zero.ToByteArray();
        Assert.True(Arrays.AreEqual(new byte[1], z));

        for (int i = 16; i <= 48; ++i)
        {
            BigInteger x = new BigInteger(i, random).SetBit(i - 1);
            byte[] b = x.ToByteArray();
            Assert.Equal((i / 8 + 1), b.Length);
            BigInteger y = new BigInteger(b);
            Assert.Equal(x, y);

            x = x.Negate();
            b = x.ToByteArray();
            Assert.Equal((i / 8 + 1), b.Length);
            y = new BigInteger(b);
            Assert.Equal(x, y);
        }
    }

    [Fact]
    public void TestToByteArrayUnsigned()
    {
        byte[] z = BigInteger.Zero.ToByteArrayUnsigned();
        Assert.Empty(z);

        for (int i = 16; i <= 48; ++i)
        {
            BigInteger x = new BigInteger(i, random).SetBit(i - 1);
            byte[] b = x.ToByteArrayUnsigned();
            Assert.Equal((i + 7) / 8, b.Length);
            BigInteger y = new BigInteger(1, b);
            Assert.Equal(x, y);

            x = x.Negate();
            b = x.ToByteArrayUnsigned();
            Assert.Equal(i / 8 + 1, b.Length);
            y = new BigInteger(b);
            Assert.Equal(x, y);
        }
    }

    [Fact]
    public void TestToString()
    {
        string s = "12345667890987654321";

        Assert.Equal(s, new BigInteger(s).ToString());
        Assert.Equal(s, new BigInteger(s, 10).ToString(10));
        Assert.Equal(s, new BigInteger(s, 16).ToString(16));

        for (int i = 0; i < 100; ++i)
        {
            BigInteger n = new BigInteger(i, random);

            Assert.Equal(n, new BigInteger(n.ToString(2), 2));
            Assert.Equal(n, new BigInteger(n.ToString(10), 10));
            Assert.Equal(n, new BigInteger(n.ToString(16), 16));
        }

        // Radix version
        int[] radices = new int[] { 2, 8, 10, 16 };
        int trials = 256;

        BigInteger[] tests = new BigInteger[trials];
        for (int i = 0; i < trials; ++i)
        {
            int len = random.Next(i + 1);
            tests[i] = new BigInteger(len, random);
        }

        foreach (int radix in radices)
        {
            for (int i = 0; i < trials; ++i)
            {
                BigInteger n1 = tests[i];
                string str = n1.ToString(radix);
                BigInteger n2 = new BigInteger(str, radix);
                Assert.Equal(n1, n2);
            }
        }
    }

    [Fact]
    public void TestValueOf()
    {
        Assert.Equal(-1, Val(-1).SignValue);
        Assert.Equal(0, Val(0).SignValue);
        Assert.Equal(1, Val(1).SignValue);

        // ValueOf(int)
        {
            for (int i = -16; i <= 16; ++i)
            {
                Assert.Equal(i, Val(i).IntValueExact);
            }

            for (int j = 0; j < 16; ++j)
            {
                int n = RandomInt32();
                Assert.Equal(n, Val(n).IntValueExact);
            }
        }

        // ValueOf(long)
        {
            for (long i = -16L; i <= 16L; ++i)
            {
                Assert.Equal(i, Val(i).LongValueExact);
            }

            for (int j = 0; j < 16; ++j)
            {
                long n = RandomInt64();
                Assert.Equal(n, Val(n).LongValueExact);
            }
        }
    }

    [Fact]
    public void TestXor()
    {
        for (int i = -16; i <= 16; ++i)
        {
            for (int j = -16; j <= 16; ++j)
            {
                Assert.Equal(Val(i ^ j), Val(i).Xor(Val(j)));
            }
        }
    }

    private static void ImplTestBytesConstructors(int expected, byte[] bytes)
    {
        var checkBE = new BigInteger(bytes, bigEndian: true);
        Assert.Equal(expected, checkBE.IntValueExact);
        Assert.Equal(expected.CompareTo(0), checkBE.SignValue);

        var checkLE = new BigInteger(Arrays.Reverse(bytes), bigEndian: false);
        Assert.Equal(expected, checkLE.IntValueExact);
        Assert.Equal(expected.CompareTo(0), checkLE.SignValue);

        int pad0 = 1 + random.Next(8), pad1 = 1 + random.Next(8);
        byte[] padded = new byte[pad0 + bytes.Length + pad1];
        random.NextBytes(padded);

        int length = bytes.Length;
        Array.Copy(bytes, 0, padded, pad0, length);

        var checkBESeg = new BigInteger(padded, pad0, length, bigEndian: true);
        Assert.Equal(expected, checkBESeg.IntValueExact);
        Assert.Equal(expected.CompareTo(0), checkBESeg.SignValue);

        var checkLESeg = new BigInteger(Arrays.Reverse(padded), pad1, length, bigEndian: false);
        Assert.Equal(expected, checkLESeg.IntValueExact);
        Assert.Equal(expected.CompareTo(0), checkLESeg.SignValue);
    }

    private static int RandomInt32() => random.Next(int.MinValue, int.MaxValue);

    private static long RandomInt64() => ((long)RandomInt32() << 32) ^ RandomInt32();

    private static BigInteger Val(int n) => BigInteger.ValueOf(n);

    private static BigInteger Val(long n) => BigInteger.ValueOf(n);

    private static BigInteger Mersenne(int e) => Two.Pow(e).Subtract(One);

    private static readonly BigInteger Zero = BigInteger.Zero;
    private static readonly BigInteger One = BigInteger.One;
    private static readonly BigInteger Two = BigInteger.Two;
    private static readonly BigInteger Three = BigInteger.Three;

    private static readonly BigInteger MinusOne = One.Negate();
    private static readonly BigInteger MinusTwo = Two.Negate();

    private static readonly int[] FirstPrimes = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29 };
    private static readonly int[] NonPrimes = { 0, 1, 4, 10, 20, 21, 22, 25, 26, 27 };

    private static readonly int[] MersennePrimeExponents = { 2, 3, 5, 7, 13, 17, 19, 31, 61, 89 };
    private static readonly int[] NonPrimeExponents = { 1, 4, 6, 9, 11, 15, 23, 29, 37, 41 };
}
