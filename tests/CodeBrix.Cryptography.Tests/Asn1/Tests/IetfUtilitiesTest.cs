using System.Text;
using CodeBrix.Cryptography.Asn1.X500.Style;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Tests; //was previously: Org.BouncyCastle.Asn1.Tests;

public class IetfUtilitiesTest
{
    [Fact]
    public void ValueToString()
    {
        IetfUtilities.ValueToString(new DerUtf8String(" "));

        // RFC 4514 escaping - also a regression guard for the linear (non O(n^2)) valueToString.
        Assert.Equal("abc", IetfUtilities.ValueToString(new DerUtf8String("abc")));
        Assert.Equal("a\\,b", IetfUtilities.ValueToString(new DerUtf8String("a,b")));
        Assert.Equal("\\,\\\"\\\\\\+\\=\\<\\>\\;", IetfUtilities.ValueToString(new DerUtf8String(",\"\\+=<>;")));
        Assert.Equal("\\ ab", IetfUtilities.ValueToString(new DerUtf8String(" ab")));
        Assert.Equal("ab\\ ", IetfUtilities.ValueToString(new DerUtf8String("ab ")));
        Assert.Equal("\\ ab\\ ", IetfUtilities.ValueToString(new DerUtf8String(" ab ")));
        Assert.Equal("\\ \\ \\ ", IetfUtilities.ValueToString(new DerUtf8String("   ")));
        Assert.Equal("a b", IetfUtilities.ValueToString(new DerUtf8String("a b")));
        Assert.Equal("\\#abc", IetfUtilities.ValueToString(new DerUtf8String("#abc")));
        Assert.Equal("a#b", IetfUtilities.ValueToString(new DerUtf8String("a#b")));

        // A large all-special value must escape every character and complete in linear time (the
        // previous insert-into-the-buffer-being-scanned loop was O(n^2)).
        int n = 100000;
        StringBuilder commas = new StringBuilder(n);
        for (int i = 0; i < n; i++)
        {
            commas.Append(',');
        }
        string escaped = IetfUtilities.ValueToString(new DerUtf8String(commas.ToString()));
        Assert.Equal(2 * n, escaped.Length);
    }
}
