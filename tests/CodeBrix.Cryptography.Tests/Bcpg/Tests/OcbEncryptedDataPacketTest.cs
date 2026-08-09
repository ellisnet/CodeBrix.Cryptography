using System;
using System.IO;
using CodeBrix.Cryptography.Bcpg;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Encoders;
using Xunit;

namespace CodeBrix.Cryptography.Bcpg.Tests; //was previously: Org.BouncyCastle.Bcpg.Tests;

public class OcbEncryptedDataPacketTest
{
    [Fact]
    public void ParseTestVector()
    {
        string testVector = "" +
            "d45301090210c265ff63a61ed8af00fa" +
            "43866be8eb9eef77241518a3d60e387b" +
            "1e283bdd90e2233d17a937a595686024" +
            "1d13ddfaccd2b724a491167631d1cd3e" +
            "a74fe5d9e617f1f267d891fd338fddb2" +
            "c66c025cde";

        MemoryStream bIn = new MemoryStream(Hex.Decode(testVector), false);
        BcpgInputStream pIn = new BcpgInputStream(bIn);

        AeadEncDataPacket p = (AeadEncDataPacket)pIn.ReadPacket();
        // TODO[pgp] Implement new packet format logic then enable this
        //Assert.True(p.HasNewPacketFormat(), "Packet length encoding format mismatch");
        Assert.Equal(1, p.Version);
        Assert.Equal(SymmetricKeyAlgorithmTag.Aes256, p.Algorithm);
        Assert.Equal(AeadAlgorithmTag.Ocb, p.AeadAlgorithm);
        Assert.Equal(16, p.ChunkSize);
        Assert.True(Arrays.AreEqual(Hex.Decode("C265FF63A61ED8AF00FA43866BE8EB"), p.GetIV()), "IV mismatch");
    }

    [Fact]
    public void ParseUnsupportedPacketVersion()
    {
        // Test vector with modified packet version 99
        string testVector = "" +
            "d45399090210c265ff63a61ed8af00fa" +
            "43866be8eb9eef77241518a3d60e387b" +
            "1e283bdd90e2233d17a937a595686024" +
            "1d13ddfaccd2b724a491167631d1cd3e" +
            "a74fe5d9e617f1f267d891fd338fddb2" +
            "c66c025cde";

        MemoryStream bIn = new MemoryStream(Hex.Decode(testVector), false);
        BcpgInputStream pIn = new BcpgInputStream(bIn);

        try
        {
            pIn.ReadPacket();
            Assert.Fail("Expected UnsupportedPacketVersionException for unsupported version 99");
        }
        catch (UnsupportedPacketVersionException)
        {
            // expected
        }
    }

    [Fact]
    public void UnsupportedChunkSize()
    {
        try
        {
            new AeadEncDataPacket(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, 20, new byte[16]);
            Assert.Fail("Expected ArgumentOutOfRangeException (chunkSize)");
        }
        catch (ArgumentOutOfRangeException e)
        {
            Assert.Equal("chunkSize", e.ParamName);
        }

        // Test vector with modified chunk size 18
        string testVector = "" +
            "d45301090212c265ff63a61ed8af00fa" +
            "43866be8eb9eef77241518a3d60e387b" +
            "1e283bdd90e2233d17a937a595686024" +
            "1d13ddfaccd2b724a491167631d1cd3e" +
            "a74fe5d9e617f1f267d891fd338fddb2" +
            "c66c025cde";

        MemoryStream bIn = new MemoryStream(Hex.Decode(testVector), false);
        BcpgInputStream pIn = new BcpgInputStream(bIn);

        try
        {
            pIn.ReadPacket();
            Assert.Fail("Expected chunkSize out of range");
        }
        catch (MalformedPacketException e)
        {
            Assert.Equal("chunkSize out of range", e.Message);
        }
    }
}
