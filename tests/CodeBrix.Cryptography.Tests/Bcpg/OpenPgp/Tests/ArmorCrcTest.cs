using System;
using System.IO;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.IO;
using Xunit;

namespace CodeBrix.Cryptography.Bcpg.OpenPgp.Tests; //was previously: Org.BouncyCastle.Bcpg.OpenPgp.Tests;

public class ArmorCrcTest
{
    private static readonly string NL = Environment.NewLine;
    private static readonly string WithoutCrc = "" +
        "-----BEGIN PGP MESSAGE-----" + NL +
        NL +
        "yxR0AAAAAABIZWxsbywgV29ybGQhCg==" + NL +
        "-----END PGP MESSAGE-----" + NL;
    private static readonly string FaultyCrc = "" +
        "-----BEGIN PGP MESSAGE-----" + NL +
        NL +
        "yxR0AAAAAABIZWxsbywgV29ybGQhCg==" + NL +
        "=TRA9" + NL +
        "-----END PGP MESSAGE-----";

    [Fact]
    public void GenerateArmorWithoutCrcSum()
    {
        MemoryStream bOut = new MemoryStream();
        ArmoredOutputStream armorOut = ArmoredOutputStream.Build()
            .EnableCrc(false)
            .Build(bOut);

        byte[] data = Strings.ToByteArray("Hello, World!\n");

        PgpLiteralDataGenerator litGen = new PgpLiteralDataGenerator();
        using (var litOut = litGen.Open(armorOut, PgpLiteralDataGenerator.Text, "", PgpLiteralData.Now,
            new byte[512]))
        {
            litOut.Write(data, 0, data.Length);
        }
        armorOut.Close();

        string result = Strings.FromByteArray(bOut.ToArray());

        Assert.Equal(WithoutCrc, result);
    }

    [Fact]
    public void ConsumeArmorWithoutCrc()
    {
        ConsumeSuccessfullyIgnoringCrcSum(WithoutCrc);
        ConsumeSuccessfullyIgnoringCrcSum(FaultyCrc);
    }

    private static void ConsumeSuccessfullyIgnoringCrcSum(string armor)
    {
        MemoryStream bIn = new MemoryStream(Strings.ToByteArray(armor), false);
        ArmoredInputStream armorIn = ArmoredInputStream.Build()
            .SetParseForHeaders(true)
            .setIgnoreCrc(true)
            .SetDetectMissingCrc(false)
            .Build(bIn);

        MemoryStream bOut = new MemoryStream();

        PgpObjectFactory objectFactory = new PgpObjectFactory(armorIn);
        PgpLiteralData literalData = (PgpLiteralData)objectFactory.NextPgpObject();
        using (Stream litIn = literalData.GetDataStream())
        {
            Streams.PipeAll(litIn, bOut);
        }
        armorIn.Close();

        string result = Strings.FromByteArray(bOut.ToArray());

        Assert.Equal("Hello, World!\n", result);
    }
}
