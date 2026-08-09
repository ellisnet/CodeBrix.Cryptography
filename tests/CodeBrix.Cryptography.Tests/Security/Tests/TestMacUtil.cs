using System;
using System.Globalization;
using System.Threading;
using CodeBrix.Cryptography.Crypto;
using Xunit;

namespace CodeBrix.Cryptography.Security.Tests; //was previously: Org.BouncyCastle.Security.Tests;

public class TestMacUtilities
{
    [Fact]
    public void TestCultureIndependence()
    {
        Thread t = Thread.CurrentThread;
        CultureInfo ci = t.CurrentCulture;
        try
        {
            /*
             * In Hungarian, the "CS" in "HMACSHA256" is linguistically a single character, so "HMAC" is not a prefix.
             */
            t.CurrentCulture = new CultureInfo("hu-HU");
            IMac mac = MacUtilities.GetMac("HMACSHA256");
            Assert.NotNull(mac);
        }
        catch (Exception e)
        {
            Assert.Fail("Culture-specific lookup failed: " + e.Message);
        }
        finally
        {
            t.CurrentCulture = ci;
        }
    }
}
