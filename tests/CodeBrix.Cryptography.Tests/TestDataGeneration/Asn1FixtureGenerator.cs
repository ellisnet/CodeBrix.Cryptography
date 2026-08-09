using System;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace CodeBrix.Cryptography.TestDataGeneration;

/// <summary>
/// Regenerates the deeply-nested ASN.1 stress fixtures under test-data/asn1/.
/// </summary>
/// <remarks>
/// ASN1SequenceParserTest feeds these to Asn1InputStream and requires it to give up with
/// "maximum nested construction level reached". Asn1InputStream.FindDepth defaults to 64,
/// so the fixtures simply have to nest deeper than that. They are pure structure with no
/// content, so writing the bytes directly is both the simplest and the clearest way to
/// produce them -- and it means these fixtures are ours rather than copied from the
/// unlicensed bc-test-data repository.
/// </remarks>
public class Asn1FixtureGenerator
{
    public static bool IsGenerationRequested =>
        Environment.GetEnvironmentVariable("CODEBRIX_CRYPTOGRAPHY_REGENERATE_TEST_DATA") == "1";

    // Comfortably past Asn1InputStream's default depth limit of 64.
    private const int NestingDepth = 100;

    [Fact(Skip = "Utility: regenerates test-data/asn1. Set " +
                 "CODEBRIX_CRYPTOGRAPHY_REGENERATE_TEST_DATA=1 to run it.",
          SkipUnless = nameof(IsGenerationRequested))]
    public void RegenerateNestedSequenceFixtures()
    {
        string dir = Path.Combine(TestDataPaths.RepositoryTestDataRoot(), "asn1");
        Directory.CreateDirectory(dir);

        File.WriteAllBytes(Path.Combine(dir, "nested_seq.der"), BuildDefiniteLengthNesting(NestingDepth));
        File.WriteAllBytes(Path.Combine(dir, "nested_seq_indef.ber"), BuildIndefiniteLengthNesting(NestingDepth));

        Assert.True(File.Exists(Path.Combine(dir, "nested_seq.der")));
        Assert.True(File.Exists(Path.Combine(dir, "nested_seq_indef.ber")));
    }

    /// <summary>
    /// DER: nested definite-length SEQUENCEs, innermost empty. Each layer wraps the one
    /// below, so the length has to be recomputed as the encoding grows.
    /// </summary>
    private static byte[] BuildDefiniteLengthNesting(int depth)
    {
        byte[] encoding = new byte[] { 0x30, 0x00 };
        for (int i = 1; i < depth; ++i)
        {
            var wrapped = new List<byte> { 0x30 };
            AppendDefiniteLength(wrapped, encoding.Length);
            wrapped.AddRange(encoding);
            encoding = wrapped.ToArray();
        }
        return encoding;
    }

    /// <summary>
    /// BER: nested indefinite-length SEQUENCEs -- "30 80" repeated, then the matching
    /// "00 00" end-of-contents octets.
    /// </summary>
    private static byte[] BuildIndefiniteLengthNesting(int depth)
    {
        var encoding = new List<byte>(depth * 4);
        for (int i = 0; i < depth; ++i)
        {
            encoding.Add(0x30);
            encoding.Add(0x80);
        }
        for (int i = 0; i < depth; ++i)
        {
            encoding.Add(0x00);
            encoding.Add(0x00);
        }
        return encoding.ToArray();
    }

    private static void AppendDefiniteLength(List<byte> output, int length)
    {
        if (length < 0x80)
        {
            output.Add((byte)length);
            return;
        }

        int byteCount = 0;
        for (int value = length; value > 0; value >>= 8)
        {
            ++byteCount;
        }

        output.Add((byte)(0x80 | byteCount));
        for (int shift = (byteCount - 1) * 8; shift >= 0; shift -= 8)
        {
            output.Add((byte)(length >> shift));
        }
    }
}
