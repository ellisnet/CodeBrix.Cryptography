using System;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Utilities.Encoders;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Tests; //was previously: Org.BouncyCastle.Asn1.Tests;

/// <summary>
/// Tests used to verify correct decoding of the ENUMERATED type.
/// </summary>
public class EnumeratedTest
{
    /// <summary>
    /// Test vector used to test decoding of multiple items.
    /// </summary>
    /// <remarks>This sample uses an ENUMERATED and a BOOLEAN.</remarks>
    private static readonly byte[] MultipleSingleByteItems = Hex.Decode("30060a01010101ff");

    /// <summary>
    /// Test vector used to test decoding of multiple items.
    /// </summary>
    /// <remarks>This sample uses two ENUMERATEDs.</remarks>
    private static readonly byte[] MultipleDoubleByteItems = Hex.Decode("30080a0201010a020202");

    /// <summary>
    /// Test vector used to test decoding of multiple items.
    /// </summary>
    /// <remarks>This sample uses an ENUMERATED and an OBJECT IDENTIFIER.</remarks>
    private static readonly byte[] MultipleTripleByteItems = Hex.Decode("300a0a0301010106032b0601");

    /// <summary>
    /// Makes sure multiple identically sized values are parsed correctly.
    /// </summary>
    [Fact]
    public void TestReadingMultipleSingleByteItems()
    {
        Asn1Object obj = Asn1Object.FromByteArray(MultipleSingleByteItems);

        Assert.True(obj is DerSequence, "Null ASN.1 SEQUENCE");

        DerSequence sequence = (DerSequence)obj;

        Assert.Equal(2, sequence.Count);

        DerEnumerated enumerated = sequence[0] as DerEnumerated;

        Assert.NotNull(enumerated);

        Assert.Equal(1, enumerated.IntValueExact);
        Assert.True(enumerated.HasValue(1), "Unexpected ENUMERATED value");

        DerBoolean boolean = sequence[1] as DerBoolean;

        Assert.NotNull(boolean);

        Assert.True(boolean.IsTrue, "Unexpected BOOLEAN value");
    }

    /// <summary>
    /// Makes sure multiple identically sized values are parsed correctly.
    /// </summary>
    [Fact]
    public void TestReadingMultipleDoubleByteItems()
    {
        Asn1Object obj = Asn1Object.FromByteArray(MultipleDoubleByteItems);

        Assert.True(obj is DerSequence, "Null ASN.1 SEQUENCE");

        DerSequence sequence = (DerSequence)obj;

        Assert.Equal(2, sequence.Count);

        DerEnumerated enumerated1 = sequence[0] as DerEnumerated;

        Assert.NotNull(enumerated1);

        Assert.Equal(257, enumerated1.IntValueExact);
        Assert.True(enumerated1.HasValue(257), "Unexpected ENUMERATED value");

        DerEnumerated enumerated2 = sequence[1] as DerEnumerated;

        Assert.NotNull(enumerated2);

        Assert.Equal(514, enumerated2.IntValueExact);
        Assert.True(enumerated2.HasValue(514), "Unexpected ENUMERATED value");
    }

    /// <summary>
    /// Makes sure multiple identically sized values are parsed correctly.
    /// </summary>
    [Fact]
    public void TestReadingMultipleTripleByteItems()
    {
        Asn1Object obj = Asn1Object.FromByteArray(MultipleTripleByteItems);

        Assert.True(obj is DerSequence, "Null ASN.1 SEQUENCE");

        DerSequence sequence = (DerSequence)obj;

        Assert.Equal(2, sequence.Count);

        DerEnumerated enumerated = sequence[0] as DerEnumerated;

        Assert.NotNull(enumerated);

        Assert.Equal(65793, enumerated.IntValueExact);
        Assert.True(enumerated.HasValue(65793), "Unexpected ENUMERATED value");

        DerObjectIdentifier objectId = sequence[1] as DerObjectIdentifier;

        Assert.NotNull(objectId);

        Assert.Equal("1.3.6.1", objectId.Id);
    }
}
