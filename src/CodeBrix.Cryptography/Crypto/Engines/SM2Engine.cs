using System;
using CodeBrix.Cryptography.Crypto.Digests;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Crypto.Utilities;
using CodeBrix.Cryptography.Math;
using CodeBrix.Cryptography.Math.EC;
using CodeBrix.Cryptography.Math.EC.Multiplier;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities;

namespace CodeBrix.Cryptography.Crypto.Engines; //was previously: Org.BouncyCastle.Crypto.Engines;

/// <summary>
/// SM2 public key encryption engine - based on https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02.
/// </summary>
public class SM2Engine
{
    public enum Mode
    {
        C1C2C3, C1C3C2
    }

    private readonly IDigest mDigest;
    private readonly Mode mMode;

    private bool mForEncryption;
    private ECKeyParameters mECKey;
    private ECDomainParameters mECParams;
    private int mCurveLength;
    private SecureRandom mRandom;

    public SM2Engine()
        : this(new SM3Digest())
    {
    }

    public SM2Engine(Mode mode)
        : this(new SM3Digest(), mode)
    {
    }

    public SM2Engine(IDigest digest)
        : this(digest, Mode.C1C2C3)
    {
    }

    public SM2Engine(IDigest digest, Mode mode)
    {
        mDigest = digest;
        mMode = mode;
    }

    public virtual void Init(bool forEncryption, ICipherParameters param)
    {
        this.mForEncryption = forEncryption;

        param = ParameterUtilities.GetRandom(param, out var providedRandom);

        mECKey = (ECKeyParameters)param;
        mECParams = mECKey.Parameters;

        if (forEncryption)
        {
            mRandom = CryptoServicesRegistrar.GetSecureRandom(providedRandom);

            ECPoint s = ((ECPublicKeyParameters)mECKey).Q.Multiply(mECParams.H);
            if (s.IsInfinity)
                throw new ArgumentException("invalid key: [h]Q at infinity");
        }
        else
        {
            mRandom = null;
        }

        mCurveLength = mECParams.Curve.FieldElementEncodingLength;
    }

    public virtual byte[] ProcessBlock(byte[] input, int inOff, int inLen)
    {
        if ((inOff + inLen) > input.Length || inLen == 0)
            throw new DataLengthException("input buffer too short");

        return ProcessBlock(input.AsSpan(inOff, inLen));
    }

    public virtual byte[] ProcessBlock(ReadOnlySpan<byte> input)
    {
        if (input.Length == 0)
            throw new DataLengthException("input buffer too short");

        if (mForEncryption)
        {
            return Encrypt(input);
        }
        else
        {
            return Decrypt(input);
        }
    }

    public virtual int GetOutputSize(int inputLen) => (1 + 2 * mCurveLength) + inputLen + mDigest.GetDigestSize();

    protected virtual ECMultiplier CreateBasePointMultiplier() => new FixedPointCombMultiplier();

    private byte[] Encrypt(ReadOnlySpan<byte> input)
    {
        byte[] c2 = input.ToArray();

        ECMultiplier multiplier = CreateBasePointMultiplier();

        BigInteger k;
        ECPoint kPB;
        do
        {
            k = NextK();
            kPB = ((ECPublicKeyParameters)mECKey).Q.Multiply(k).Normalize();

            Kdf(mDigest, kPB, c2);
        }
        while (NotEncrypted(c2, input));

        ECPoint c1P = multiplier.Multiply(mECParams.G, k).Normalize();

        int c1PEncodedLength = c1P.GetEncodedLength(false);
        Span<byte> c1 = c1PEncodedLength <= 512
            ? stackalloc byte[c1PEncodedLength]
            : new byte[c1PEncodedLength];
        c1P.EncodeTo(false, c1);

        AddFieldElement(mDigest, kPB.AffineXCoord);
        mDigest.BlockUpdate(input);
        AddFieldElement(mDigest, kPB.AffineYCoord);

        int digestSize = mDigest.GetDigestSize();
        Span<byte> c3 = digestSize <= 128
            ? stackalloc byte[digestSize]
            : new byte[digestSize];
        mDigest.DoFinal(c3);

        switch (mMode)
        {
        case Mode.C1C3C2:
            return Arrays.Concatenate(c1, c3, c2);
        default:
            return Arrays.Concatenate(c1, c2, c3);
        }
    }

    private byte[] Decrypt(ReadOnlySpan<byte> input)
    {
        int digestSize = mDigest.GetDigestSize();

        // The SM2 ciphertext is C1 (an encoded point, curveLength*2+1 bytes) || C3 (a digest) || C2;
        // reject an input too short to hold C1 and C3 rather than over-read or underflow.
        int c1Length = mCurveLength * 2 + 1;
        if (input.Length < c1Length + digestSize)
            throw new InvalidCipherTextException("data too short");

        ECPoint c1P = mECParams.Curve.DecodePoint(input[..c1Length]);

        ECPoint s = c1P.Multiply(mECParams.H);
        if (s.IsInfinity)
            throw new InvalidCipherTextException("[h]C1 at infinity");

        c1P = c1P.Multiply(((ECPrivateKeyParameters)mECKey).D).Normalize();

        int c2Length = input.Length - c1Length - digestSize;
        byte[] c2 = new byte[c2Length];

        if (mMode == Mode.C1C3C2)
        {
            input[(c1Length + digestSize)..].CopyTo(c2);
        }
        else
        {
            input[c1Length..(c1Length + c2Length)].CopyTo(c2);
        }

        Kdf(mDigest, c1P, c2);

        AddFieldElement(mDigest, c1P.AffineXCoord);
        mDigest.BlockUpdate(c2);
        AddFieldElement(mDigest, c1P.AffineYCoord);

        Span<byte> c3 = digestSize <= 128
            ? stackalloc byte[digestSize]
            : new byte[digestSize];
        mDigest.DoFinal(c3);

        int check = 0;
        if (mMode == Mode.C1C3C2)
        {
            for (int i = 0; i != c3.Length; i++)
            {
                check |= c3[i] ^ input[c1Length + i];
            }
        }
        else
        {
            for (int i = 0; i != c3.Length; i++)
            {
                check |= c3[i] ^ input[c1Length + c2.Length + i];
            }
        }

        c3.Fill(0);

        if (check != 0)
        {
            Arrays.Fill(c2, 0);
            throw new InvalidCipherTextException("invalid cipher text");
        }

        return c2;
    }

    private bool NotEncrypted(ReadOnlySpan<byte> encData, ReadOnlySpan<byte> input)
    {
        for (int i = 0; i != encData.Length; i++)
        {
            if (encData[i] != input[i])
                return false;
        }

        return true;
    }

    private void Kdf(IDigest digest, ECPoint c1, byte[] encData)
    {
        int digestSize = digest.GetDigestSize();
        int bufSize = System.Math.Max(4, digestSize);
        Span<byte> buf = bufSize <= 128
            ? stackalloc byte[bufSize]
            : new byte[bufSize];
        int off = 0;

        IMemoable memo = digest as IMemoable;
        IMemoable copy = null;

        if (memo != null)
        {
            AddFieldElement(digest, c1.AffineXCoord);
            AddFieldElement(digest, c1.AffineYCoord);
            copy = memo.Copy();
        }

        uint ct = 0;

        while (off < encData.Length)
        {
            if (memo != null)
            {
                memo.Reset(copy);
            }
            else
            {
                AddFieldElement(digest, c1.AffineXCoord);
                AddFieldElement(digest, c1.AffineYCoord);
            }

            int xorLen = System.Math.Min(digestSize, encData.Length - off);

            Pack.UInt32_To_BE(++ct, buf);
            digest.BlockUpdate(buf[..4]);
            digest.DoFinal(buf);
            Bytes.XorTo(xorLen, buf, encData.AsSpan(off));
            off += xorLen;
        }
    }

    private BigInteger NextK()
    {
        int qBitLength = mECParams.N.BitLength;

        BigInteger k;
        do
        {
            k = BigIntegers.CreateRandomBigInteger(qBitLength, mRandom);
        }
        while (k.SignValue == 0 || k.CompareTo(mECParams.N) >= 0);

        return k;
    }

    private void AddFieldElement(IDigest digest, ECFieldElement v)
    {
        int encodedLength = v.GetEncodedLength();
        Span<byte> p = encodedLength <= 128
            ? stackalloc byte[encodedLength]
            : new byte[encodedLength];
        v.EncodeTo(p);
        digest.BlockUpdate(p);
    }
}
