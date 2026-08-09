using System.IO;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Tests; //was previously: Org.BouncyCastle.Asn1.Tests;

public class Asn1SequenceParserTest
{
    private static readonly byte[] seqData = Hex.Decode("3006020100060129");
    private static readonly byte[] nestedSeqData = Hex.Decode("300b0201000601293003020101");
    private static readonly byte[] expTagSeqData = Hex.Decode("a1083006020100060129");
    private static readonly byte[] implTagSeqData = Hex.Decode("a106020100060129");
    private static readonly byte[] nestedSeqExpTagData = Hex.Decode("300d020100060129a1053003020101");
    private static readonly byte[] nestedSeqImpTagData = Hex.Decode("300b020100060129a103020101");

    private static readonly byte[] berSeqData = Hex.Decode("30800201000601290000");
    private static readonly byte[] berDerNestedSeqData = Hex.Decode("308002010006012930030201010000");
    private static readonly byte[] berNestedSeqData = Hex.Decode("3080020100060129308002010100000000");
    private static readonly byte[] berExpTagSeqData = Hex.Decode("a180308002010006012900000000");
    private static readonly byte[] berSeqWithDERNullData = Hex.Decode("308005000201000601290000");

    [Fact]
    public void DerWriting()
    {
        MemoryStream bOut = new MemoryStream();
        using (var seqGen = new DerSequenceGenerator(bOut))
        {
            seqGen.AddObject(DerInteger.Zero);
            seqGen.AddObject(new DerObjectIdentifier("1.1"));
        }

        Assert.True(Arrays.AreEqual(seqData, bOut.ToArray()), "basic DER writing test failed.");
    }

    [Fact]
    public void NestedDerWriting()
    {
        MemoryStream bOut = new MemoryStream();
        using (var seqGen1 = new DerSequenceGenerator(bOut))
        {
            seqGen1.AddObject(DerInteger.Zero);
            seqGen1.AddObject(new DerObjectIdentifier("1.1"));

            using (var seqGen2 = new DerSequenceGenerator(seqGen1.GetRawOutputStream()))
            {
                seqGen2.AddObject(DerInteger.One);
            }
        }

        Assert.True(Arrays.AreEqual(nestedSeqData, bOut.ToArray()), "nested DER writing test failed.");
    }

    [Fact]
    public void DerExplicitTaggedSequenceWriting()
    {
        MemoryStream bOut = new MemoryStream();
        using (var seqGen = new DerSequenceGenerator(bOut, 1, true))
        {
            seqGen.AddObject(DerInteger.Zero);
            seqGen.AddObject(new DerObjectIdentifier("1.1"));
        }

        Assert.True(Arrays.AreEqual(expTagSeqData, bOut.ToArray()), "explicit tag writing test failed.");
    }

    [Fact]
    public void DerImplicitTaggedSequenceWriting()
    {
        MemoryStream bOut = new MemoryStream();
        using (var seqGen = new DerSequenceGenerator(bOut, 1, false))
        {
            seqGen.AddObject(DerInteger.Zero);
            seqGen.AddObject(new DerObjectIdentifier("1.1"));
        }

        Assert.True(Arrays.AreEqual(implTagSeqData, bOut.ToArray()), "implicit tag writing test failed.");
    }

    [Fact]
    public void NestedExplicitTagDerWriting()
    {
        MemoryStream bOut = new MemoryStream();
        using (var seqGen1 = new DerSequenceGenerator(bOut))
        {
            seqGen1.AddObject(DerInteger.Zero);
            seqGen1.AddObject(new DerObjectIdentifier("1.1"));

            using (var seqGen2 = new DerSequenceGenerator(seqGen1.GetRawOutputStream(), 1, true))
            {
                seqGen2.AddObject(DerInteger.One);
            }
        }

        Assert.True(Arrays.AreEqual(nestedSeqExpTagData, bOut.ToArray()), "nested explicit tagged DER writing test failed.");
    }

    [Fact]
    public void NestedImplicitTagDerWriting()
    {
        MemoryStream bOut = new MemoryStream();
        using (var seqGen1 = new DerSequenceGenerator(bOut))
        {
            seqGen1.AddObject(DerInteger.Zero);
            seqGen1.AddObject(new DerObjectIdentifier("1.1"));

            using (var seqGen2 = new DerSequenceGenerator(seqGen1.GetRawOutputStream(), 1, false))
            {
                seqGen2.AddObject(DerInteger.One);
            }
        }

        Assert.True(Arrays.AreEqual(nestedSeqImpTagData, bOut.ToArray()), "nested implicit tagged DER writing test failed.");
    }

    [Fact]
    public void BerWriting()
    {
        MemoryStream bOut = new MemoryStream();
        using (var seqGen = new BerSequenceGenerator(bOut))
        {
            seqGen.AddObject(DerInteger.Zero);
            seqGen.AddObject(new DerObjectIdentifier("1.1"));
        }

        Assert.True(Arrays.AreEqual(berSeqData, bOut.ToArray()), "basic BER writing test failed.");
    }

    [Fact]
    public void NestedBerDerWriting()
    {
        MemoryStream bOut = new MemoryStream();
        using (var seqGen1 = new BerSequenceGenerator(bOut))
        {
            seqGen1.AddObject(DerInteger.Zero);
            seqGen1.AddObject(new DerObjectIdentifier("1.1"));

            using (var seqGen2 = new DerSequenceGenerator(seqGen1.GetRawOutputStream()))
            {
                seqGen2.AddObject(DerInteger.One);
            }
        }

        Assert.True(Arrays.AreEqual(berDerNestedSeqData, bOut.ToArray()), "nested BER/DER writing test failed.");
    }

    [Fact]
    public void NestedBerWriting()
    {
        MemoryStream bOut = new MemoryStream();
        using (var seqGen1 = new BerSequenceGenerator(bOut))
        {
            seqGen1.AddObject(DerInteger.Zero);
            seqGen1.AddObject(new DerObjectIdentifier("1.1"));

            using (var seqGen2 = new BerSequenceGenerator(seqGen1.GetRawOutputStream()))
            {
                seqGen2.AddObject(DerInteger.One);
            }
        }

        Assert.True(Arrays.AreEqual(berNestedSeqData, bOut.ToArray()), "nested BER writing test failed.");
    }

    [Fact]
    public void DerReading()
    {
        Asn1StreamParser aIn = new Asn1StreamParser(seqData);
        Asn1SequenceParser seq = (Asn1SequenceParser)aIn.ReadObject();
        int count = 0;

        Assert.NotNull(seq);

        object o;
        while ((o = seq.ReadObject()) != null)
        {
            switch (count)
            {
            case 0:
                Assert.True(o is DerInteger);
                break;
            case 1:
                Assert.True(o is DerObjectIdentifier);
                break;
            }
            count++;
        }

        Assert.Equal(2, count);
    }

    [Fact]
    public void NestedDerReading() => ImplNestedReading(nestedSeqData);

    [Fact]
    public void BerReading()
    {
        Asn1StreamParser aIn = new Asn1StreamParser(berSeqData);
        Asn1SequenceParser seq = (Asn1SequenceParser)aIn.ReadObject();
        int count = 0;

        Assert.NotNull(seq);

        object o;
        while ((o = seq.ReadObject()) != null)
        {
            switch (count)
            {
            case 0:
                Assert.True(o is DerInteger);
                break;
            case 1:
                Assert.True(o is DerObjectIdentifier);
                break;
            }
            count++;
        }

        Assert.Equal(2, count);
    }

    [Fact]
    public void NestedBerDerReading() => ImplNestedReading(berDerNestedSeqData);

    [Fact]
    public void NestedBerReading() => ImplNestedReading(berNestedSeqData);

    [Fact]
    public void BerExplicitTaggedSequenceWriting()
    {
        MemoryStream bOut = new MemoryStream();
        using (var seqGen = new BerSequenceGenerator(bOut, 1, true))
        {
            seqGen.AddObject(DerInteger.Zero);
            seqGen.AddObject(new DerObjectIdentifier("1.1"));
        }

        Assert.True(Arrays.AreEqual(berExpTagSeqData, bOut.ToArray()), "explicit BER tag writing test failed.");
    }

    [Fact]
    public void HeavilyDLNestedSequence()
    {
        try
        {
            Asn1Sequence seq = Asn1Sequence.GetInstance(
                new Asn1InputStream(SimpleTest.FindTestResource("asn1", "nested_seq.der")).ReadObject());
            Assert.Fail("no exception");
        }
        catch (Asn1Exception e)
        {
            Assert.Equal("maximum nested construction level reached", e.Message);
        }
    }

    [Fact]
    public void HeavilyBerNestedSequence()
    {
        try
        {
            Asn1Sequence seq = Asn1Sequence.GetInstance(
                new Asn1InputStream(SimpleTest.FindTestResource("asn1", "nested_seq_indef.ber")).ReadObject());
            Assert.Fail("no exception");
        }
        catch (Asn1Exception e)
        {
            Assert.Equal("maximum nested construction level reached", e.Message);
        }
    }

    [Fact]
    public void SequenceWithDerNullReading() => ImplParseWithNull(berSeqWithDERNullData);

    private static void ImplNestedReading(byte[] data)
    {
        Asn1StreamParser aIn = new Asn1StreamParser(data);
        Asn1SequenceParser seq = (Asn1SequenceParser)aIn.ReadObject();
        int count = 0;

        Assert.NotNull(seq);

        object o;
        while ((o = seq.ReadObject()) != null)
        {
            switch (count)
            {
            case 0:
                Assert.True(o is DerInteger);
                break;
            case 1:
                Assert.True(o is DerObjectIdentifier);
                break;
            case 2:
                Assert.True(o is Asn1SequenceParser);

                Asn1SequenceParser s = (Asn1SequenceParser)o;

                // NB: Must exhaust the nested parser
                while (s.ReadObject() != null)
                {
                    // Ignore
                }

                break;
            }
            count++;
        }

        Assert.Equal(3, count);
    }

    private static void ImplParseWithNull(byte[] data)
    {
        Asn1StreamParser aIn = new Asn1StreamParser(data);
        Asn1SequenceParser seq = (Asn1SequenceParser)aIn.ReadObject();
        int count = 0;

        Assert.NotNull(seq);

        object o;
        while ((o = seq.ReadObject()) != null)
        {
            switch (count)
            {
            case 0:
                Assert.True(o is Asn1Null);
                break;
            case 1:
                Assert.True(o is DerInteger);
                break;
            case 2:
                Assert.True(o is DerObjectIdentifier);
                break;
            }
            count++;
        }

        Assert.Equal(3, count);
    }
}
