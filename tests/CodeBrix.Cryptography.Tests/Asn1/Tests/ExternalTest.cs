using System.IO;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Tests; //was previously: Org.BouncyCastle.Asn1.Tests;

/// <summary>
/// Tests used to verify correct decoding of the EXTERNAL type.
/// </summary>
public class ExternalTest
{
    [Fact]
    public void ConstructorInvalidCast()
    {
        // Enforce that this (very) malformed input results in an ASN1Exception (via failed DerExternal constructor).

        // 6 bytes: SEQUENCE { CONSTRUCTED(0x28) { SEQUENCE {} } }
        byte[] badEncoding = { 0x30, 0x04, 0x28, 0x02, 0x30, 0x00 };

        try
        {
            Asn1Object.FromByteArray(badEncoding);
            Assert.Fail("Asn1Exception expected");
        }
        catch (Asn1Exception)
        {
            // expected
        }
        catch (IOException)
        {
            Assert.Fail("Asn1Exception expected");
        }
    }

    // TODO[asn1] More tests per DLExternalTest in bc-java
}
