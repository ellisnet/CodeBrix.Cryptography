using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using CodeBrix.Cryptography.Crypto.Digests;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities;

namespace CodeBrix.Cryptography.Crypto.Kems.MLKem; //was previously: Org.BouncyCastle.Crypto.Kems.MLKem;

internal sealed class MLKemEngine
{
    private readonly IndCpa m_indCpa;

    // Constant Parameters
    internal const int N = 256;
    internal const int Q = 3329;
    internal const int QInv = 62209;

    internal const int SymBytes = 32;
    internal const int SharedSecretBytes = 32;

    internal const int PolyBytes = 384;

    internal const int Eta2 = 2;

    internal const int SeedBytes = SymBytes * 2;

    // Parameters
    internal int K { get; private set; }
    internal int PolyVecBytes { get; private set; }
    internal int PolyCompressedBytes { get; private set; }
    internal int PolyVecCompressedBytes { get; private set; }
    internal int Eta1 { get; private set; }
    internal int IndCpaPublicKeyBytes { get; private set; }
    internal int IndCpaSecretKeyBytes { get; private set; }
    internal int PublicKeyBytes => IndCpaPublicKeyBytes;
    internal int SecretKeyBytes { get; private set; }
    internal int CipherTextBytes { get; private set; }

    internal MLKemEngine(int k)
    {
        K = k;
        switch (k)
        {
        case 2:
            Eta1 = 3;
            PolyCompressedBytes = 128;
            PolyVecCompressedBytes = K * 320;
            break;
        case 3:
            Eta1 = 2;
            PolyCompressedBytes = 128;
            PolyVecCompressedBytes = K * 320;
            break;
        case 4:
            Eta1 = 2;
            PolyCompressedBytes = 160;
            PolyVecCompressedBytes = K * 352;
            break;
        default:
            throw new ArgumentException("K: " + k + " is not supported for ML-KEM", nameof(k));
        }

        PolyVecBytes = k * PolyBytes;
        IndCpaPublicKeyBytes = PolyVecBytes + SymBytes;
        IndCpaSecretKeyBytes = PolyVecBytes;
        CipherTextBytes = PolyVecCompressedBytes + PolyCompressedBytes;
        SecretKeyBytes = IndCpaSecretKeyBytes + IndCpaPublicKeyBytes + 2 * SymBytes;

        m_indCpa = new IndCpa(this);
    }

    internal bool CheckDecapKeyHash(byte[] decapKey)
    {
        int k = K, k384 = k * 384, k768 = k * 768;

        byte[] kH = new byte[SymBytes];
        H(decapKey.AsSpan(k384, k384 + 32), kH.AsSpan());

        return Arrays.FixedTimeEquals(SymBytes, kH, 0, decapKey, k768 + 32);
    }

    internal bool CheckEncapKeyModulus(byte[] encapKey) => PolyVec.CheckModulus(this, t: encapKey) < 0;

    internal byte[] CopyEncapKey(byte[] decapKey) =>
        Arrays.CopySegment(decapKey, IndCpaSecretKeyBytes, PublicKeyBytes);

    internal void GenerateKemKeyPair(SecureRandom random, out byte[] seed, out byte[] encoding)
    {
        seed = SecureRandom.GetNextBytes(random, SymBytes * 2);

        GenerateKemKeyPairInternal(seed, out encoding);
    }

    internal void GenerateKemKeyPairInternal(byte[] seed, out byte[] encoding)
    {
        Debug.Assert(seed.Length == SeedBytes);

        encoding = new byte[SecretKeyBytes];

        m_indCpa.GenerateKeyPair(seed, encoding);

        H(encoding.AsSpan(IndCpaSecretKeyBytes, IndCpaPublicKeyBytes),
            encoding.AsSpan(SecretKeyBytes - SymBytes * 2));

        Array.Copy(seed, SymBytes, encoding, SecretKeyBytes - SymBytes, SymBytes);
    }

    internal static void G(ReadOnlySpan<byte> input, Span<byte> output) =>
        ImplDigest(new Sha3Digest(512), input, output);

    private static void H(ReadOnlySpan<byte> input, Span<byte> output) =>
        ImplDigest(new Sha3Digest(256), input, output);

    private static void ImplDigest(Sha3Digest digest, ReadOnlySpan<byte> input, Span<byte> output)
    {
        digest.BlockUpdate(input);
        digest.DoFinal(output);
    }

    internal void KemDecrypt(ReadOnlySpan<byte> decapKey, ReadOnlySpan<byte> encapsulation, Span<byte> secret)
    {
        Debug.Assert(decapKey.Length == SecretKeyBytes);

        // TODO Input validation?
        Span<byte> buf = stackalloc byte[2 * SymBytes];
        m_indCpa.Decrypt(encapsulation, decapKey, buf);
        decapKey.Slice(SecretKeyBytes - 2 * SymBytes, SymBytes).CopyTo(buf[SymBytes..]);

        Span<byte> kr = stackalloc byte[2 * SymBytes];
        G(buf, kr);

        Span<byte> cmp = stackalloc byte[CipherTextBytes];
        ReadOnlySpan<byte> pk = decapKey.Slice(IndCpaSecretKeyBytes, IndCpaPublicKeyBytes);

        m_indCpa.Encrypt(pk, buf[..SymBytes], kr[SymBytes..], cmp);

        int fail = ~FixedTimeEquals(cmp, encapsulation);

        // if ciphertexts do not match, “implicitly reject”
        {
            Span<byte> implicitRejection = stackalloc byte[SharedSecretBytes];

            // J(z||c)
            var xof = new ShakeDigest(256);
            xof.BlockUpdate(decapKey.Slice(SecretKeyBytes - SymBytes, SymBytes));
            xof.BlockUpdate(encapsulation);
            xof.OutputFinal(implicitRejection);

            CMov(kr, implicitRejection, SharedSecretBytes, fail);
        }

        kr[..SharedSecretBytes].CopyTo(secret);
    }

    internal void KemEncrypt(ReadOnlySpan<byte> encapKey, ReadOnlySpan<byte> randBytes, Span<byte> encapsulation,
        Span<byte> secret)
    {
        Debug.Assert(encapKey.Length == PublicKeyBytes);
        Debug.Assert(randBytes.Length == SymBytes);

        Span<byte> buf = stackalloc byte[2 * SymBytes];
        Span<byte> kr = stackalloc byte[2 * SymBytes];

        randBytes[..SymBytes].CopyTo(buf);

        H(encapKey, buf[SymBytes..]);

        G(buf, kr);

        m_indCpa.Encrypt(encapKey, buf[..SymBytes], kr[SymBytes..], encapsulation);

        kr[..SharedSecretBytes].CopyTo(secret);
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static void CMov(Span<byte> r, ReadOnlySpan<byte> x, int xLen, int cond)
    {
        Debug.Assert(0 == cond || -1 == cond);

        for (int i = 0; i < xLen; ++i)
        {
            int r_i = r[i], diff = r_i ^ x[i];
            r_i ^= diff & cond;
            r[i] = (byte)r_i;
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static int FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        int d = 0;
        for (int i = 0, len = a.Length; i < len; ++i)
        {
            d |= a[i] ^ b[i];
        }
        d |= d >> 16;
        d &= 0xFFFF;
        return (d - 1) >> 31;
    }
}
