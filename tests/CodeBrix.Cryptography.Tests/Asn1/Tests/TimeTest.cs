using System;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Tests; //was previously: Org.BouncyCastle.Asn1.Tests;

public class TimeTest
{
	[Fact]
	public void CheckCmsTimeVsX509Time()
	{
		DateTime now = DateTime.UtcNow;

		// Time classes only have a resolution of seconds
		now = SimpleTest.MakeUtcDateTime(now.Year, now.Month, now.Day, now.Hour, now.Minute, now.Second);

        Cms.Time cmsTime = new Cms.Time(now);
		X509.Time x509Time = new X509.Time(now);

		Assert.Equal(now, cmsTime.ToDateTime());
		Assert.Equal(now, x509Time.ToDateTime());
	}
}
