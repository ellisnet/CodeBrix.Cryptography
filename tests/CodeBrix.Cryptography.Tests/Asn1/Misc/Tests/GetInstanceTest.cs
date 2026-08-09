using System;
using CodeBrix.Cryptography.Asn1.Crmf;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Misc.Tests; //was previously: Org.BouncyCastle.Asn1.Misc.Tests;

public class GetInstanceTest
{
    [Fact]
    public void OptionalValidityAtLeastOne()
    {
        // RFC 4211: OptionalValidity requires at least one of notBefore/notAfter.
        // An empty SEQUENCE must be rejected on decode, matching the constructor.
        try
        {
            OptionalValidity.GetInstance(DerSequence.Empty);
            Assert.Fail("empty OptionalValidity SEQUENCE accepted on decode");
        }
        catch (ArgumentException e)
        {
            Assert.NotNull(e.Message);
            Assert.True(e.Message.StartsWith("at least one of notBefore/notAfter MUST be present."), "exception message");
        }
    }
}
