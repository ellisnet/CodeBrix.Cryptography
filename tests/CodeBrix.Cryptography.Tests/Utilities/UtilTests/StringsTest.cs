using Xunit;

namespace CodeBrix.Cryptography.Utilities.UtilTests; //was previously: Org.BouncyCastle.Utilities.UtilTests;

public class StringsTest
{
    [Fact]
    public void SplitConsecutiveDelimiters() => CheckSplit("a..b", '.', "a", "", "b");

    [Fact]
    public void SplitDomainWithLeadingDot() =>
        CheckSplit(".example.domain.com", '.', "", "example", "domain", "com");

    [Fact]
    public void SplitLeadingDelimiter() => CheckSplit(".permitted", '.', "", "permitted");

    [Fact]
    public void SplitNoDelimiters() => CheckSplit("nodots", '.', "nodots");

    [Fact]
    public void SplitNormalDomain() => CheckSplit("example.domain.com", '.', "example", "domain", "com");

    [Fact]
    public void SplitOnlyDelimiter() => CheckSplit(".", '.', "", "");

    [Fact]
    public void SplitTrailingDelimiter() => CheckSplit("trailing.", '.', "trailing", "");

    private static void CheckSplit(string input, char delimiter, params string[] expected) =>
        Assert.Equal(expected, Strings.Split(input, delimiter));
}
