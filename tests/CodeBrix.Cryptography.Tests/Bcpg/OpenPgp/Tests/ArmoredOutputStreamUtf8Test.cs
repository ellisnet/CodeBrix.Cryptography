using System;
using System.IO;
using CodeBrix.Cryptography.Utilities;
using Xunit;

namespace CodeBrix.Cryptography.Bcpg.OpenPgp.Tests; //was previously: Org.BouncyCastle.Bcpg.OpenPgp.Tests;

public class ArmoredOutputStreamUtf8Test
{
    [Fact]
    public void Basic()
    {
        // Hex.decode("c384c396c39cc39f26556d6c61757473")
        string utf8WithUmlauts = "ÄÖÜß&Umlauts";

        MemoryStream buf = new MemoryStream();
        using (ArmoredOutputStream armorOut = new ArmoredOutputStream(buf))
        {
            armorOut.SetHeader("Comment", utf8WithUmlauts);
            armorOut.Write(Strings.ToUtf8ByteArray("Foo\nBar"));
        }

        byte[] armoredOutputUTF8 = buf.ToArray();

        string comment = FindComment(armoredOutputUTF8);
        string[] headers = ParseHeaders(armoredOutputUTF8);

        Assert.NotNull(comment);
        Assert.Equal(utf8WithUmlauts, comment);

        // round-tripped comment from ascii armor input stream
        Assert.Equal(utf8WithUmlauts, headers[1].Substring("Comment: ".Length));
    }

    private string FindComment(byte[] armoredOutputUTF8)
    {
        using (var br = new StreamReader(new MemoryStream(armoredOutputUTF8, false), Strings.UTF8))
        {
            String comment = null;
            String line;
            while ((line = br.ReadLine()) != null)
            {
                if (line.StartsWith("Comment: "))
                {
                    comment = line.Substring("Comment: ".Length);
                    break;
                }
            }
            return comment;
        }
    }

    private string[] ParseHeaders(byte[] armoredOutput)
    {
        MemoryStream bytesIn = new MemoryStream(armoredOutput);
        using (ArmoredInputStream armorIn = new ArmoredInputStream(bytesIn))
        {
            return armorIn.GetArmorHeaders();
        }
    }
}
