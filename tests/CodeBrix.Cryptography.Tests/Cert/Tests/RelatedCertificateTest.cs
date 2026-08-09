using System;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Cms;
using CodeBrix.Cryptography.Asn1.Pkcs;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Utilities.Date;
using Xunit;

namespace CodeBrix.Cryptography.Cert.Tests; //was previously: Org.BouncyCastle.Cert.Tests;

public class RelatedCertificateTest
{
    // =====================================================================
    // OID + extension constants
    // =====================================================================

    [Fact]
    public void OidValues()
    {
        Assert.Equal("1.3.6.1.5.5.7.1.36", X509ObjectIdentifiers.id_pe_relatedCert.GetID());
        Assert.Equal("1.3.6.1.5.5.7.1.36", X509Extensions.RelatedCertificate.GetID());
        Assert.Equal(X509ObjectIdentifiers.id_pe_relatedCert, X509Extensions.RelatedCertificate);
        Assert.Equal("1.2.840.113549.1.9.16.2.60", PkcsObjectIdentifiers.IdAARelatedCertRequest.GetID());
    }

    // =====================================================================
    // BinaryTime
    // =====================================================================

    [Fact]
    public void BinaryTimeRoundTrip()
    {
        // Pick a fixed epoch-second value to anchor the wire encoding.
        long sec = 1700000000L;
        BinaryTime t = new BinaryTime(sec);
        Assert.True(t.Time.HasValue(sec));

        BinaryTime reparsed = BinaryTime.GetInstance(t.GetEncoded());
        Assert.Equal(t, reparsed);
        Assert.True(reparsed.Time.HasValue(sec));

        BinaryTime fromDateTime = new BinaryTime(DateTimeUtilities.UnixMsToDateTime(sec * 1000L));
        Assert.Equal(t, fromDateTime);
        Assert.Equal(sec * 1000L, DateTimeUtilities.DateTimeToUnixMs(fromDateTime.GetDateTime()));
        Assert.True(fromDateTime.TryGetDateTime(out var tryDateTime));
        Assert.Equal(sec * 1000L, DateTimeUtilities.DateTimeToUnixMs(tryDateTime));
    }

    [Fact]
    public void BinaryTimeRejectsNegative()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new BinaryTime(-1L));

        Assert.Throws<ArgumentOutOfRangeException>(() => new BinaryTime(DerInteger.ValueOf(-1L)));

        var preEpoch = DateTimeUtilities.UnixEpoch.AddSeconds(-1);
        Assert.Throws<ArgumentOutOfRangeException>(() => new BinaryTime(preEpoch));
    }
}
