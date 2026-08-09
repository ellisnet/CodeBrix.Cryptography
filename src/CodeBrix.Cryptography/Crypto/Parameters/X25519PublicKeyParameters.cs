using System;
using System.IO;
using CodeBrix.Cryptography.Math.EC.Rfc7748;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.IO;

namespace CodeBrix.Cryptography.Crypto.Parameters; //was previously: Org.BouncyCastle.Crypto.Parameters;

/// <summary>
/// X25519 public key (RFC 7748). Holds the 32-byte u-coordinate of the peer's curve point. The
/// encoding is stored verbatim; validation of the point is performed during scalar multiplication
/// in the agreement primitive.
/// </summary>
public sealed class X25519PublicKeyParameters
    : AsymmetricKeyParameter
{
    /// <summary>Length in bytes of an X25519 public key encoding (32).</summary>
    public static readonly int KeySize = X25519.PointSize;

    private readonly byte[] data = new byte[KeySize];

    /// <summary>Construct from a 32-byte buffer holding the encoded u-coordinate.</summary>
    /// <exception cref="ArgumentException">If <paramref name="buf"/> length differs from
    /// <see cref="KeySize"/>.</exception>
    public X25519PublicKeyParameters(byte[] buf)
        : this(Validate(buf), 0)
    {
    }

    /// <summary>Construct from <paramref name="buf"/> at <paramref name="off"/>; reads
    /// <see cref="KeySize"/> bytes.</summary>
    public X25519PublicKeyParameters(byte[] buf, int off)
        : base(false)
    {
        Array.Copy(buf, off, data, 0, KeySize);
    }

    /// <summary>Construct from a span holding the encoded u-coordinate.</summary>
    /// <exception cref="ArgumentException">If <paramref name="buf"/> length differs from
    /// <see cref="KeySize"/>.</exception>
    public X25519PublicKeyParameters(ReadOnlySpan<byte> buf)
        : base(false)
    {
        if (buf.Length != KeySize)
            throw new ArgumentException("must have length " + KeySize, nameof(buf));

        buf.CopyTo(data);
    }

    /// <summary>Read the 32-byte encoded u-coordinate from <paramref name="input"/>.</summary>
    /// <exception cref="EndOfStreamException">If the stream ends before <see cref="KeySize"/>
    /// bytes have been read.</exception>
    public X25519PublicKeyParameters(Stream input)
        : base(false)
    {
        if (KeySize != Streams.ReadFully(input, data))
            throw new EndOfStreamException("EOF encountered in middle of X25519 public key");
    }

    /// <summary>
    /// Write the 32-byte encoded u-coordinate into <paramref name="buf"/> at <paramref name="off"/>.
    /// </summary>
    public void Encode(byte[] buf, int off)
    {
        Array.Copy(data, 0, buf, off, KeySize);
    }

    /// <summary>Write the 32-byte encoded u-coordinate into the supplied span.</summary>
    public void Encode(Span<byte> buf)
    {
        data.CopyTo(buf);
    }

    /// <summary>Return a fresh copy of the 32-byte encoded u-coordinate.</summary>
    public byte[] GetEncoded()
    {
        return Arrays.Clone(data);
    }

    internal ReadOnlySpan<byte> DataSpan => data;

    internal ReadOnlyMemory<byte> DataMemory => data;

    private static byte[] Validate(byte[] buf)
    {
        if (buf.Length != KeySize)
            throw new ArgumentException("must have length " + KeySize, nameof(buf));

        return buf;
    }
}
