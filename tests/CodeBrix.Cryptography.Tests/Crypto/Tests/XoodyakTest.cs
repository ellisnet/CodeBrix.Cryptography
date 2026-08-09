using System;
using System.Collections.Generic;
using System.IO;
using CodeBrix.Cryptography.Crypto.Digests;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Crypto.Tests; //was previously: Org.BouncyCastle.Crypto.Tests;

public class XoodyakTest
{
    [Fact(Skip = "Explicit test in the upstream NUnit suite; not run by default. Remove Skip to run it.")]
    public void BenchDigest()
    {
        var xoodyak = new XoodyakDigest();

        byte[] data = new byte[1024];
        for (int i = 0; i < 1024; ++i)
        {
            for (int j = 0; j < 1024; ++j)
            {
                // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                xoodyak.BlockUpdate(data);
            }

            // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            xoodyak.DoFinal(data);
        }
    }

    [Fact]
    public void TestExceptionsDigest()
    {
        var xoodyak = new XoodyakDigest();

        try
        {
            xoodyak.BlockUpdate(new byte[1], 1, 1);
            Assert.Fail(xoodyak.AlgorithmName + ": input for BlockUpdate is too short");
        }
        catch (DataLengthException)
        {
            //expected
        }

        try
        {
            xoodyak.DoFinal(new byte[xoodyak.GetDigestSize() - 1], 2);
            Assert.Fail(xoodyak.AlgorithmName + ": output for DoFinal is too short");
        }
        catch (OutputLengthException)
        {
            //expected
        }
    }

    [Fact]
    public void TestParametersDigest()
    {
        var xoodyak = new XoodyakDigest();

        Assert.Equal(32, xoodyak.GetDigestSize());
    }

    [Fact]
    public void TestVectorsDigest()
    {
        Random random = new Random();
        var xoodyak = new XoodyakDigest();
        var map = new Dictionary<string, string>();
        using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.xoodyak.LWC_HASH_KAT_256.txt")))
        {
            string line;
            while ((line = src.ReadLine()) != null)
            {
                int eqPos = line.IndexOf('=');
                if (eqPos >= 0)
                {
                    var key = line.Substring(0, eqPos).Trim();
                    var val = line.Substring(eqPos + 1).Trim();
                    map[key] = val;
                    continue;
                }

                string count = map["Count"];
                byte[] ptByte = Hex.Decode(map["Msg"]);
                byte[] expected = Hex.Decode(map["MD"]);
                map.Clear();

                byte[] hash = new byte[xoodyak.GetDigestSize()];

                xoodyak.BlockUpdate(ptByte, 0, ptByte.Length);
                xoodyak.DoFinal(hash, 0);
                Assert.True(Arrays.AreEqual(expected, hash));

                if (ptByte.Length > 1)
                {
                    int split = random.Next(1, ptByte.Length);
                    xoodyak.BlockUpdate(ptByte, 0, split);
                    xoodyak.BlockUpdate(ptByte, split, ptByte.Length - split);
                    xoodyak.DoFinal(hash, 0);
                    Assert.True(Arrays.AreEqual(expected, hash));
                }
            }
        }
    }
}
