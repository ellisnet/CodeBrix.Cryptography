using System;
using CodeBrix.Cryptography.Crypto.Parameters;

namespace CodeBrix.Cryptography.Crypto.Modes; //was previously: Org.BouncyCastle.Crypto.Modes;

/// <summary>
/// Implements a Cipher-FeedBack (CFB) mode on top of a simple block cipher.
/// </summary>
public class CfbBlockCipher
    : IBlockCipherMode
{
    private byte[]	IV;
    private byte[]	cfbV;
    private byte[]	cfbOutV;
	private bool	encrypting;

	private readonly int			blockSize;
    private readonly IBlockCipher	cipher;

    /// <summary>
    /// Basic constructor.
    /// </summary>
    /// <param name="cipher">The block cipher to be used as the basis of the feedback mode.</param>
    /// <param name="bitBlockSize">The block size in bits (must be a multiple of 8).</param>
    public CfbBlockCipher(
        IBlockCipher cipher,
        int          bitBlockSize)
    {
        if (bitBlockSize < 8 || (bitBlockSize & 7) != 0)
            throw new ArgumentException("CFB" + bitBlockSize + " not supported", "bitBlockSize");

        this.cipher = cipher;
        this.blockSize = bitBlockSize / 8;
        this.IV = new byte[cipher.GetBlockSize()];
        this.cfbV = new byte[cipher.GetBlockSize()];
        this.cfbOutV = new byte[cipher.GetBlockSize()];
    }
    /// <summary>
    /// The underlying block cipher that we are wrapping.
    /// </summary>
    /// <returns>The underlying block cipher that we are wrapping.</returns>
    public IBlockCipher UnderlyingCipher => cipher;

    /// <summary>
    /// Initialise the cipher and, possibly, the initialisation vector (IV).
    /// </summary>
    /// <param name="forEncryption">If true the cipher is initialised for encryption, if false for decryption.
    /// </param>
    /// <param name="parameters">The key and other data required by the cipher.</param>
    /// <exception cref="ArgumentException">If the parameters argument is inappropriate.</exception>
    public void Init(
        bool forEncryption,
        ICipherParameters parameters)
    {
        this.encrypting = forEncryption;
        if (parameters is ParametersWithIV ivParam)
        {
            byte[] iv = ivParam.GetIV();
            int diff = IV.Length - iv.Length;
            Array.Copy(iv, 0, IV, diff, iv.Length);
            Array.Clear(IV, 0, diff);

            parameters = ivParam.Parameters;
        }
        Reset();

        // if it's null, key is to be reused.
        if (parameters != null)
        {
            cipher.Init(true, parameters);
        }
    }

    /// <summary>
    /// The algorithm name and mode.
    /// </summary>
    /// <returns>The name of the underlying algorithm followed by "/CFB" and the block size in bits.</returns>
    public string AlgorithmName
    {
        get { return cipher.AlgorithmName + "/CFB" + (blockSize * 8); }
    }

    /// <summary>
    /// Indicates whether partial blocks are okay for this mode.
    /// </summary>
    public bool IsPartialBlockOkay
    {
        get { return true; }
    }

    /// <summary>
    /// Return the block size we are operating at.
    /// </summary>
    /// <returns>The block size we are operating at (in bytes).</returns>
    public int GetBlockSize()
    {
        return blockSize;
    }

    /// <summary>
    /// Process a block of data.
    /// </summary>
    /// <param name="input">The input buffer.</param>
    /// <param name="inOff">The offset into the input buffer.</param>
    /// <param name="output">The output buffer.</param>
    /// <param name="outOff">The offset into the output buffer.</param>
    /// <returns>The number of bytes processed.</returns>
    public int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
    {
        return encrypting
            ? EncryptBlock(input.AsSpan(inOff), output.AsSpan(outOff))
            : DecryptBlock(input.AsSpan(inOff), output.AsSpan(outOff));
    }

    /// <summary>
    /// Process a block of data using Spans.
    /// </summary>
    /// <param name="input">The input span.</param>
    /// <param name="output">The output span.</param>
    /// <returns>The number of bytes processed.</returns>
    public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        return encrypting
            ? EncryptBlock(input, output)
            : DecryptBlock(input, output);
    }

    private int EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Check.DataLength(input, blockSize, "input buffer too short");
        Check.OutputLength(output, blockSize, "output buffer too short");

        cipher.ProcessBlock(cfbV, cfbOutV);
        //
        // XOR the cfbV with the plaintext producing the ciphertext
        //
        for (int i = 0; i < blockSize; i++)
        {
            output[i] = (byte)(cfbOutV[i] ^ input[i]);
        }
        //
        // change over the input block.
        //
        Array.Copy(cfbV, blockSize, cfbV, 0, cfbV.Length - blockSize);
        output[..blockSize].CopyTo(cfbV.AsSpan(cfbV.Length - blockSize));
        return blockSize;
    }

    private int DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Check.DataLength(input, blockSize, "input buffer too short");
        Check.OutputLength(output, blockSize, "output buffer too short");

        cipher.ProcessBlock(cfbV, 0, cfbOutV, 0);
        //
        // change over the input block.
        //
        Array.Copy(cfbV, blockSize, cfbV, 0, cfbV.Length - blockSize);
        input[..blockSize].CopyTo(cfbV.AsSpan(cfbV.Length - blockSize));
        //
        // XOR the cfbV with the ciphertext producing the plaintext
        //
        for (int i = 0; i < blockSize; i++)
        {
            output[i] = (byte)(cfbOutV[i] ^ input[i]);
        }
        return blockSize;
    }

    /// <summary>
    /// Reset the chaining vector back to the IV and reset the underlying cipher.
    /// </summary>
    public void Reset()
    {
        Array.Copy(IV, 0, cfbV, 0, IV.Length);
    }
}
