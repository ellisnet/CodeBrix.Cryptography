using System;
using CodeBrix.Cryptography.Asn1.Cms;
using CodeBrix.Cryptography.Utilities;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Microsoft.Tests; //was previously: Org.BouncyCastle.Asn1.Microsoft.Tests;

public class TimeStampRequestTest
{
    [Fact]
    public void All()
    {
        ContentInfo content = new ContentInfo(CmsObjectIdentifiers.Data,
            new DerOctetString(new byte[]{ 1, 2, 3, 4 }));

        // convenience constructor - standard countersignature type, no attributes
        TimeStampRequest req = new TimeStampRequest(content);
        TimeStampRequest reqResult = TimeStampRequest.GetInstance(req.GetEncoded());

        Assert.Equal(MicrosoftObjectIdentifiers.MicrosoftTimeStampRequest, reqResult.CountersignatureType);
        Assert.Null(reqResult.Attributes);
        Assert.True(Arrays.AreEqual(content.GetEncoded(), reqResult.Content.GetEncoded()), "content");

        // full constructor, attributes present
        Asn1EncodableVector v = new Asn1EncodableVector();
        v.Add(new Asn1.Cms.Attribute(CmsAttributes.ContentType, new DerSet(CmsObjectIdentifiers.Data)));
        Attributes attributes = new Attributes(v);

        req = new TimeStampRequest(new DerObjectIdentifier("1.2.3.4"), attributes, content);
        reqResult = TimeStampRequest.GetInstance(req.GetEncoded());

        Assert.Equal(new DerObjectIdentifier("1.2.3.4"), reqResult.CountersignatureType);
        Assert.True(Arrays.AreEqual(attributes.GetEncoded(Asn1Encodable.Der),
            reqResult.Attributes.GetEncoded(Asn1Encodable.Der)), "attributes");
        Assert.True(Arrays.AreEqual(content.GetEncoded(), reqResult.Content.GetEncoded()), "content");

        Assert.Equal(reqResult, TimeStampRequest.GetInstance(reqResult));
        Assert.Null(TimeStampRequest.GetInstance(null));

        try
        {
            TimeStampRequest.GetInstance(DerSequence.Empty);
            Assert.Fail("sequence length 0 accepted");
        }
        catch (ArgumentException e)
        {
            Assert.NotNull(e.Message);
            Assert.True(e.Message.StartsWith("Bad sequence size: 0"), "exception message");
        }

        Asn1EncodableVector big = new Asn1EncodableVector();
        big.Add(MicrosoftObjectIdentifiers.MicrosoftTimeStampRequest);
        big.Add(attributes);
        big.Add(content);
        big.Add(content);

        try
        {
            TimeStampRequest.GetInstance(new DerSequence(big));
            Assert.Fail("sequence length 4 accepted");
        }
        catch (ArgumentException e)
        {
            Assert.NotNull(e.Message);
            Assert.True(e.Message.StartsWith("Bad sequence size: 4"), "exception message");
        }
    }
}
