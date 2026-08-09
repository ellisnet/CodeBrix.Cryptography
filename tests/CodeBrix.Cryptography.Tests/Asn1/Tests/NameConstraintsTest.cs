using System;
using CodeBrix.Cryptography.Asn1.X509;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Tests; //was previously: Org.BouncyCastle.Asn1.Tests;

public class NameConstraintsTest
{
    [Fact]
    public void EmptySequenceRejection()
    {
        // GeneralSubtree ::= SEQUENCE { base GeneralName, ... } - base is mandatory, so an empty
        // sequence is malformed and must be rejected with a clean ArgumentException rather than an unchecked
        // IndexOutOfRangeException escaping the parse path.
        try
        {
            GeneralSubtree.GetInstance(DerSequence.Empty);
            Assert.Fail("empty GeneralSubtree accepted");
        }
        catch (ArgumentException e)
        {
            Assert.NotNull(e.Message);
            Assert.StartsWith("Bad sequence size: 0", e.Message);
        }
    }

    [Fact]
    public void EmptyExcludedSubtreesRejection()
    {
        // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree (RFC 5280 sec. 4.2.1.10):
        // an empty permittedSubtrees [0] must be rejected.
        try
        {
            NameConstraints.GetInstance(new DerSequence(new DerTaggedObject(false, 1, DerSequence.Empty)));
            Assert.Fail("empty permittedSubtrees accepted");
        }
        catch (ArgumentException e)
        {
            Assert.NotNull(e.Message);
            Assert.StartsWith("Minimum sequence size ", e.Message);
        }
    }

    [Fact]
    public void EmptyPermittedSubtreesRejection()
    {
        // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree (RFC 5280 sec. 4.2.1.10):
        // an empty permittedSubtrees [0] must be rejected.
        try
        {
            NameConstraints.GetInstance(new DerSequence(new DerTaggedObject(false, 0, DerSequence.Empty)));
            Assert.Fail("empty permittedSubtrees accepted");
        }
        catch (ArgumentException e)
        {
            Assert.NotNull(e.Message);
            Assert.StartsWith("Minimum sequence size ", e.Message);
        }
    }

    [Fact]
    public void Roundtrip()
    {
        // a valid non-empty NameConstraints still round-trips through the parse path.
        GeneralSubtree subtree = new GeneralSubtree(new GeneralName(GeneralName.DnsName, "test.example.com"));
        NameConstraints nc = new NameConstraints(new GeneralSubtrees(subtree), null);

        NameConstraints parsed = NameConstraints.GetInstance(nc.ToAsn1Object());
        Assert.NotNull(parsed.PermittedSubtreesValue);
        Assert.Single(parsed.PermittedSubtreesValue.Elements);
        Assert.Null(parsed.ExcludedSubtreesValue);
    }
}
