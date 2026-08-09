using CodeBrix.Cryptography.Math;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Date;
using CodeBrix.Cryptography.Utilities.Encoders;
using Xunit;

namespace CodeBrix.Cryptography.Tsp.Tests; //was previously: Org.BouncyCastle.Tsp.Tests;

public class TimeStampTokenInfoUnitTest
{
	private static readonly byte[] tstInfo1 = Hex.Decode(
		  "303e02010106022a033021300906052b0e03021a050004140000000000000000000000000000000000000000"
		+ "020118180f32303035313130313038313732315a");

	private static readonly byte[] tstInfo2 = Hex.Decode(
		  "304c02010106022a033021300906052b0e03021a05000414ffffffffffffffffffffffffffffffffffffffff"
		+ "020117180f32303035313130313038323934355a3009020103800101810102020164");

	private static readonly byte[] tstInfo3 = Hex.Decode(
		  "304f02010106022a033021300906052b0e03021a050004140000000000000000000000000000000000000000"
		+ "020117180f32303035313130313038343733355a30090201038001018101020101ff020164");

	private static readonly byte[] tstInfoDudDate = Hex.Decode(
		  "303e02010106022a033021300906052b0e03021a050004140000000000000000000000000000000000000000"
        + "020118180f32303030563130313038313732315a");

	[Fact]
	public void TestTstInfo1()
	{
		TimeStampTokenInfo tstInfo = CreateTimeStampTokenInfo(tstInfo1);

		//
		// verify
		//
		GenTimeAccuracy accuracy = tstInfo.GenTimeAccuracy;

		Assert.Null(accuracy);

		Assert.Equal(new BigInteger("24"), tstInfo.SerialNumber);

		Assert.Equal(1130833041000L, DateTimeUtilities.DateTimeToUnixMs(tstInfo.GenTime));

		Assert.Equal("1.2.3", tstInfo.Policy);

		Assert.False(tstInfo.IsOrdered);

		Assert.Null(tstInfo.Nonce);

		Assert.Equal(TspAlgorithms.Sha1, tstInfo.MessageImprintAlgOid);

		Assert.True(Arrays.AreEqual(new byte[20], tstInfo.GetMessageImprintDigest()));

		Assert.True(Arrays.AreEqual(tstInfo1, tstInfo.GetEncoded()));
	}

    [Fact]
	public void TestTstInfo2()
	{
		TimeStampTokenInfo tstInfo = CreateTimeStampTokenInfo(tstInfo2);

		//
		// verify
		//
		GenTimeAccuracy accuracy = tstInfo.GenTimeAccuracy;

		Assert.Equal(3, accuracy.Seconds);
		Assert.Equal(1, accuracy.Millis);
		Assert.Equal(2, accuracy.Micros);

		Assert.Equal(new BigInteger("23"), tstInfo.SerialNumber);

		Assert.Equal(1130833785000L, DateTimeUtilities.DateTimeToUnixMs(tstInfo.GenTime));

		Assert.Equal("1.2.3", tstInfo.Policy);

		Assert.False(tstInfo.IsOrdered);

		Assert.Equal(tstInfo.Nonce, BigInteger.ValueOf(100));

		Assert.True(Arrays.AreEqual(
			Hex.Decode("ffffffffffffffffffffffffffffffffffffffff"),
			tstInfo.GetMessageImprintDigest()));

		Assert.True(Arrays.AreEqual(tstInfo2, tstInfo.GetEncoded()));
	}

    [Fact]
	public void TestTstInfo3()
	{
		TimeStampTokenInfo tstInfo = CreateTimeStampTokenInfo(tstInfo3);

		//
		// verify
		//
		GenTimeAccuracy accuracy = tstInfo.GenTimeAccuracy;

		Assert.Equal(3, accuracy.Seconds);
		Assert.Equal(1, accuracy.Millis);
		Assert.Equal(2, accuracy.Micros);

		Assert.Equal(new BigInteger("23"), tstInfo.SerialNumber);

		Assert.Equal(1130834855000L, DateTimeUtilities.DateTimeToUnixMs(tstInfo.GenTime));

		Assert.Equal("1.2.3", tstInfo.Policy);

		Assert.True(tstInfo.IsOrdered);

		Assert.Equal(tstInfo.Nonce, BigInteger.ValueOf(100));

		Assert.Equal(TspAlgorithms.Sha1, tstInfo.MessageImprintAlgOid);

		Assert.True(Arrays.AreEqual(new byte[20], tstInfo.GetMessageImprintDigest()));

		Assert.True(Arrays.AreEqual(tstInfo3, tstInfo.GetEncoded()));
	}

	[Fact]
	public void TestTstInfoDudDate()
	{
		try
		{
			CreateTimeStampTokenInfo(tstInfoDudDate);

			Assert.Fail("dud date not detected.");
		}
		catch (TspException)
		{
			// expected
		}
	}

	private TimeStampTokenInfo CreateTimeStampTokenInfo(byte[] tstInfo)
	{
		return new TimeStampTokenInfo(tstInfo);
	}
}
