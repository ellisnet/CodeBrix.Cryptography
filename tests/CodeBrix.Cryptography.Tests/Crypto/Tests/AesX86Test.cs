using Xunit;
// NOTE: .NET Core 3.1 is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP3_0_OR_GREATER
using System;

using CodeBrix.Cryptography.Crypto.Engines;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;

namespace CodeBrix.Cryptography.Crypto.Tests; //was previously: Org.BouncyCastle.Crypto.Tests;

public class AesX86Test
    : CipherTest
{
    private static SimpleTest[] CreateBlockCipherVectors() => new SimpleTest[]
    {
        CreateVectorTest(0, "80000000000000000000000000000000", "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
        CreateVectorTest(1, "00000000000000000000000000000080", "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
        CreateMonteCarloTest(2, 10000, "00000000000000000000000000000000", "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
        CreateMonteCarloTest(3, 10000, "5F060D3716B345C253F6749ABAC10917", "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
        CreateVectorTest(4, "000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
        CreateMonteCarloTest(5, 10000, "AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114", "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
        CreateVectorTest(6, "0000000000000000000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
        CreateMonteCarloTest(7, 10000, "28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168"),
        CreateVectorTest(8, "80000000000000000000000000000000", "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
        CreateVectorTest(9, "00000000000000000000000000000080", "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
        CreateMonteCarloTest(10, 10000, "00000000000000000000000000000000", "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
        CreateMonteCarloTest(11, 10000, "5F060D3716B345C253F6749ABAC10917", "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
        CreateVectorTest(12, "000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
        CreateMonteCarloTest(13, 10000, "AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114", "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
        CreateVectorTest(14, "0000000000000000000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
        CreateMonteCarloTest(15, 10000, "28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168"),
        CreateVectorTest(16, "80000000000000000000000000000000", "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
        CreateVectorTest(17, "00000000000000000000000000000080", "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
        CreateMonteCarloTest(18, 10000, "00000000000000000000000000000000", "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
        CreateMonteCarloTest(19, 10000, "5F060D3716B345C253F6749ABAC10917", "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
        CreateVectorTest(20, "000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
        CreateMonteCarloTest(21, 10000, "AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114", "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
        CreateVectorTest(22, "0000000000000000000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
        CreateMonteCarloTest(23, 10000, "28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168")
    };

    private static SimpleTest CreateMonteCarloTest(int id, int iters, string key, string input, string output) =>
        new BlockCipherMonteCarloTest(id, iters, new AesEngine_X86(), HexKey(key), input, output);

    private static SimpleTest CreateVectorTest(int id, string key, string input, string output) =>
        new BlockCipherVectorTest(id, new AesEngine_X86(), HexKey(key), input, output);

    private static KeyParameter HexKey(string key) => new KeyParameter(Hex.DecodeStrict(key));

    private readonly SecureRandom Random = new SecureRandom();

    // Upstream skipped the whole fixture from [OneTimeSetUp] when the CPU has no
    // AES-NI; xUnit does the same declaratively through SkipUnless.
    public static bool IsAesX86Supported => AesEngine_X86.IsSupported;

    public override string Name => "AesX86";

    [Fact(Skip = "Explicit test in the upstream NUnit suite; not run by default. Remove Skip to run it.")]
    public void BenchDecrypt128() => ImplBenchProcess(forEncryption: false, keySize: 128);

    [Fact(Skip = "Explicit test in the upstream NUnit suite; not run by default. Remove Skip to run it.")]
    public void BenchDecrypt192() => ImplBenchProcess(forEncryption: false, keySize: 192);

    [Fact(Skip = "Explicit test in the upstream NUnit suite; not run by default. Remove Skip to run it.")]
    public void BenchDecrypt256() => ImplBenchProcess(forEncryption: false, keySize: 256);

    [Fact(Skip = "Explicit test in the upstream NUnit suite; not run by default. Remove Skip to run it.")]
    public void BenchDecryptFour128() => ImplBenchProcessFour(forEncryption: false, keySize: 128);

    [Fact(Skip = "Explicit test in the upstream NUnit suite; not run by default. Remove Skip to run it.")]
    public void BenchDecryptFour192() => ImplBenchProcessFour(forEncryption: false, keySize: 192);

    [Fact(Skip = "Explicit test in the upstream NUnit suite; not run by default. Remove Skip to run it.")]
    public void BenchDecryptFour256() => ImplBenchProcessFour(forEncryption: false, keySize: 256);

    [Fact(Skip = "Explicit test in the upstream NUnit suite; not run by default. Remove Skip to run it.")]
    public void BenchEncrypt128() => ImplBenchProcess(forEncryption: true, keySize: 128);

    [Fact(Skip = "Explicit test in the upstream NUnit suite; not run by default. Remove Skip to run it.")]
    public void BenchEncrypt192() => ImplBenchProcess(forEncryption: true, keySize: 192);

    [Fact(Skip = "Explicit test in the upstream NUnit suite; not run by default. Remove Skip to run it.")]
    public void BenchEncrypt256() => ImplBenchProcess(forEncryption: true, keySize: 256);

    [Fact(Skip = "Explicit test in the upstream NUnit suite; not run by default. Remove Skip to run it.")]
    public void BenchEncryptFour128() => ImplBenchProcessFour(forEncryption: true, keySize: 128);

    [Fact(Skip = "Explicit test in the upstream NUnit suite; not run by default. Remove Skip to run it.")]
    public void BenchEncryptFour192() => ImplBenchProcessFour(forEncryption: true, keySize: 192);

    [Fact(Skip = "Explicit test in the upstream NUnit suite; not run by default. Remove Skip to run it.")]
    public void BenchEncryptFour256() => ImplBenchProcessFour(forEncryption: true, keySize: 256);

    [Fact(Skip = "Requires x86 AES-NI hardware support.", SkipUnless = nameof(IsAesX86Supported))]
    public void BlockCipherVectors() => RunTests(CreateBlockCipherVectors());

    [Fact(Skip = "Requires x86 AES-NI hardware support.", SkipUnless = nameof(IsAesX86Supported))]
    public void EngineChecks128() => ImplEngineChecks(keySize: 128);

    [Fact(Skip = "Requires x86 AES-NI hardware support.", SkipUnless = nameof(IsAesX86Supported))]
    public void EngineChecks192() => ImplEngineChecks(keySize: 192);

    [Fact(Skip = "Requires x86 AES-NI hardware support.", SkipUnless = nameof(IsAesX86Supported))]
    public void EngineChecks256() => ImplEngineChecks(keySize: 256);

    [Fact(Skip = "Requires x86 AES-NI hardware support.", SkipUnless = nameof(IsAesX86Supported))]
    public void FourBlocksDecrypt128() => ImplTestFourBlocks(forEncryption: false, keySize: 128);

    [Fact(Skip = "Requires x86 AES-NI hardware support.", SkipUnless = nameof(IsAesX86Supported))]
    public void FourBlocksDecrypt192() => ImplTestFourBlocks(forEncryption: false, keySize: 192);

    [Fact(Skip = "Requires x86 AES-NI hardware support.", SkipUnless = nameof(IsAesX86Supported))]
    public void FourBlocksDecrypt256() => ImplTestFourBlocks(forEncryption: false, keySize: 256);

    [Fact(Skip = "Requires x86 AES-NI hardware support.", SkipUnless = nameof(IsAesX86Supported))]
    public void FourBlocksEncrypt128() => ImplTestFourBlocks(forEncryption: true, keySize: 128);

    [Fact(Skip = "Requires x86 AES-NI hardware support.", SkipUnless = nameof(IsAesX86Supported))]
    public void FourBlocksEncrypt192() => ImplTestFourBlocks(forEncryption: true, keySize: 192);

    [Fact(Skip = "Requires x86 AES-NI hardware support.", SkipUnless = nameof(IsAesX86Supported))]
    public void FourBlocksEncrypt256() => ImplTestFourBlocks(forEncryption: true, keySize: 256);

    private void ImplBenchProcess(bool forEncryption, int keySize)
    {
        var engine = RandomEngine(forEncryption, keySize);
        Span<byte> data = stackalloc byte[16];
        Random.NextBytes(data);
        for (int i = 0; i < 1000000000; ++i)
        {
            engine.ProcessBlock(data, data);
        }
    }

    private void ImplBenchProcessFour(bool forEncryption, int keySize)
    {
        var engine = RandomEngine(forEncryption, keySize);
        Span<byte> data = stackalloc byte[64];
        Random.NextBytes(data);
        for (int i = 0; i < 1000000000 / 4; ++i)
        {
            engine.ProcessFourBlocks(data, data);
        }
    }

    private void ImplEngineChecks(int keySize) => RunEngineChecks(new AesEngine_X86(), RandomKey(keySize));

    private void ImplTestFourBlocks(bool forEncryption, int keySize)
    {
        Span<byte> data = stackalloc byte[64];
        Span<byte> fourBlockOutput = stackalloc byte[64];
        Span<byte> singleBlockOutput = stackalloc byte[64];

        for (int i = 0; i < 100; ++i)
        {
            Random.NextBytes(data);

            var engine = RandomEngine(forEncryption, keySize);

            engine.ProcessFourBlocks(data, fourBlockOutput);

            for (int j = 0; j < 64; j += 16)
            {
                engine.ProcessBlock(data[j..], singleBlockOutput[j..]);
            }

            Assert.True(fourBlockOutput.SequenceEqual(singleBlockOutput));
        }
    }

    private AesEngine_X86 RandomEngine(bool forEncryption, int keySize)
    {
        var engine = new AesEngine_X86();
        engine.Init(forEncryption, RandomKey(keySize));
        return engine;
    }

    private KeyParameter RandomKey(int keySize) => KeyParameter.Create(keySize / 8, Random, SecureRandom.Fill);
}
