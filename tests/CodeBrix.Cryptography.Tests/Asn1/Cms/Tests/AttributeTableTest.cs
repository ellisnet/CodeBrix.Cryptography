using System;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Cms.Tests; //was previously: Org.BouncyCastle.Asn1.Cms.Tests;

public class AttributeTableTest
{
    private static readonly DerObjectIdentifier type1 = new DerObjectIdentifier("1.1.1");
    private static readonly DerObjectIdentifier type2 = new DerObjectIdentifier("1.1.2");
    private static readonly DerObjectIdentifier type3 = new DerObjectIdentifier("1.1.3");

    [Fact]
    public void Basic()
    {
        Asn1EncodableVector v = new Asn1EncodableVector(
            new Asn1.Cms.Attribute(type1, new DerSet(type1)),
            new Asn1.Cms.Attribute(type2, new DerSet(type2)));

        AttributeTable table = new AttributeTable(v);

        Assert.Equal(2, table.Count);

        Assert.True(table.HasAny(type1));
        Assert.True(table.HasAny(type2));
        Assert.False(table.HasAny(type3));

        Asn1.Cms.Attribute a1 = table[type1];
        Assert.NotNull(a1);
        Assert.Equal(new DerSet(type1), a1.AttrValues);

        Asn1.Cms.Attribute a2 = table[type2];
        Assert.NotNull(a2);
        Assert.Equal(new DerSet(type2), a2.AttrValues);

        Asn1.Cms.Attribute a3 = table[type3];
        Assert.Null(a3);

        Asn1EncodableVector vec1 = table.GetAll(type1);
        Assert.Single(vec1);

        Asn1EncodableVector vec3 = table.GetAll(type3);
        Assert.Empty(vec3);

        Asn1EncodableVector vec = table.ToAsn1EncodableVector();
        Assert.Equal(2, vec.Count);

        var t = table.ToDictionary();
        Assert.Equal(2, t.Count);

        // multiple

        v = new Asn1EncodableVector(
            new Asn1.Cms.Attribute(type1, new DerSet(type1)),
            new Asn1.Cms.Attribute(type1, new DerSet(type2)),
            new Asn1.Cms.Attribute(type1, new DerSet(type3)),
            new Asn1.Cms.Attribute(type2, new DerSet(type2)));

        table = new AttributeTable(v);

        Assert.Equal(4, table.Count);

        Assert.True(table.HasAny(type1));
        Assert.True(table.HasAny(type2));
        Assert.False(table.HasAny(type3));

        a1 = table[type1];
        Assert.Equal(new DerSet(type1), a1.AttrValues);

        vec = table.GetAll(type1);
        Assert.Equal(3, vec.Count);

        Asn1.Cms.Attribute a;

        a = (Asn1.Cms.Attribute)vec[0];
        Assert.Equal(new DerSet(type1), a.AttrValues);

        a = (Asn1.Cms.Attribute)vec[1];
        Assert.Equal(new DerSet(type2), a.AttrValues);

        a = (Asn1.Cms.Attribute)vec[2];
        Assert.Equal(new DerSet(type3), a.AttrValues);

        vec = table.GetAll(type2);
        Assert.Single(vec);

        vec = table.ToAsn1EncodableVector();
        Assert.Equal(4, vec.Count);

        // Attribute.GetInstance must reject a structurally-valid SEQUENCE whose type element is not an
        // OBJECT IDENTIFIER (here a tagged object) with ArgumentException, rather than leak an
        // InvalidCastException from the (DerObjectIdentifier) cast out of the GetInstance contract.
        DerSequence badAttr = DerSequence.FromElements(
            new DerTaggedObject(0, new DerOctetString(new byte[]{ 1, 2, 3 })),
            new DerSet());
        try
        {
            Asn1.Cms.Attribute.GetInstance(badAttr);
            Assert.Fail("Attribute.GetInstance accepted a non-OID type element");
        }
        catch (ArgumentException)
        {
            // expected - documented malformed reject
        }
    }
}
