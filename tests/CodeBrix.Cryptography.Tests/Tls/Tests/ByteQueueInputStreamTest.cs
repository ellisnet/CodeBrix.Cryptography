using System;
using CodeBrix.Cryptography.Utilities;
using Xunit;

namespace CodeBrix.Cryptography.Tls.Tests; //was previously: Org.BouncyCastle.Tls.Tests;

public class ByteQueueInputStreamTest
{
    [Fact]
    public void TestAvailable()
    {
        ByteQueueInputStream input = new ByteQueueInputStream();

        // buffer is empty
        Assert.Equal(0, input.Available);

        // after adding once
        input.AddBytes(new byte[10]);
        Assert.Equal(10, input.Available);

        // after adding more than once
        input.AddBytes(new byte[5]);
        Assert.Equal(15, input.Available);

        // after reading a single byte
        input.ReadByte();
        Assert.Equal(14, input.Available);

        // after reading into a byte array
        Assert.Equal(4, input.Read(new byte[4], 0, 4));
        Assert.Equal(10, input.Available);

        input.Close();
    }

    [Fact]
    public void TestSkip()
    {
        ByteQueueInputStream input = new ByteQueueInputStream();

        // skip when buffer is empty
        Assert.Equal(0, input.Skip(10));

        // skip equal to available
        input.AddBytes(new byte[2]);
        Assert.Equal(2, input.Skip(2));
        Assert.Equal(0, input.Available);

        // skip less than available
        input.AddBytes(new byte[10]);
        Assert.Equal(5, input.Skip(5));
        Assert.Equal(5, input.Available);

        // skip more than available
        Assert.Equal(5, input.Skip(20));
        Assert.Equal(0, input.Available);

        input.Close();
    }

    [Fact]
    public void TestRead()
    {
        ByteQueueInputStream input = new ByteQueueInputStream();
        input.AddBytes(new byte[]{ 0x01, 0x02 });
        input.AddBytes(new byte[]{ 0x03 });

        Assert.Equal(0x01, input.ReadByte());
        Assert.Equal(0x02, input.ReadByte());
        Assert.Equal(0x03, input.ReadByte());
        Assert.Equal(-1, input.ReadByte());

        input.Close();
    }

    [Fact]
    public void TestReadArray()
    {
        ByteQueueInputStream input = new ByteQueueInputStream();
        input.AddBytes(new byte[]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 });

        byte[] buffer = new byte[5];

        // read less than available into specified position
        Assert.Equal(1, input.Read(buffer, 2, 1));
        AssertArrayEquals(new byte[]{ 0x00, 0x00, 0x01, 0x00, 0x00 }, buffer);

        // read equal to available
        Assert.Equal(5, input.Read(buffer, 0, buffer.Length));
        AssertArrayEquals(new byte[]{ 0x02, 0x03, 0x04, 0x05, 0x06 }, buffer);

        // read more than available
        input.AddBytes(new byte[]{ 0x01, 0x02, 0x03 });
        Assert.Equal(3, input.Read(buffer, 0, buffer.Length));
        AssertArrayEquals(new byte[]{ 0x01, 0x02, 0x03, 0x05, 0x06 }, buffer);

        input.Close();
    }

    [Fact]
    public void TestPeek()
    {
        ByteQueueInputStream input = new ByteQueueInputStream();

        byte[] buffer = new byte[5];

        // peek more than available
        Assert.Equal(0, input.Peek(buffer));
        AssertArrayEquals(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00 }, buffer);

        // peek less than available
        input.AddBytes(new byte[]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 });
        Assert.Equal(5, input.Peek(buffer));
        AssertArrayEquals(new byte[]{ 0x01, 0x02, 0x03, 0x04, 0x05 }, buffer);
        Assert.Equal(6, input.Available);

        // peek equal to available
        input.ReadByte();
        Assert.Equal(5, input.Peek(buffer));
        AssertArrayEquals(new byte[]{ 0x02, 0x03, 0x04, 0x05, 0x06 }, buffer);
        Assert.Equal(5, input.Available);

        input.Close();
    }

    private static void AssertArrayEquals(byte[] a, byte[] b)
    {
        Assert.True(Arrays.AreEqual(a, b));
    }
}
