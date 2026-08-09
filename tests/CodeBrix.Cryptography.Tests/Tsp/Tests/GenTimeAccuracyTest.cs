using System;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Tsp;
using Xunit;

namespace CodeBrix.Cryptography.Tsp.Tests; //was previously: Org.BouncyCastle.Tsp.Tests;

public class GenTimeAccuracyUnitTest
{
	private static readonly DerInteger ZERO_VALUE = DerInteger.Zero;
	private static readonly DerInteger ONE_VALUE = DerInteger.One;
	private static readonly DerInteger TWO_VALUE = DerInteger.Two;
	private static readonly DerInteger THREE_VALUE = DerInteger.Three;

	[Fact]
	public void TestOneTwoThree()
	{
		GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ONE_VALUE, TWO_VALUE, THREE_VALUE));

		checkValues(accuracy, ONE_VALUE, TWO_VALUE, THREE_VALUE);

		checkTostring(accuracy, "1.002003");
	}

	[Fact]
	public void TestThreeTwoOne()
	{
		GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(THREE_VALUE, TWO_VALUE, ONE_VALUE));

		checkValues(accuracy, THREE_VALUE, TWO_VALUE, ONE_VALUE);

		checkTostring(accuracy, "3.002001");
	}

	[Fact]
	public void TestTwoThreeTwo()
	{
		GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(TWO_VALUE, THREE_VALUE, TWO_VALUE));

		checkValues(accuracy, TWO_VALUE, THREE_VALUE, TWO_VALUE);

		checkTostring(accuracy, "2.003002");
	}

	[Fact]
	public void TestZeroTwoThree()
	{
		GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ZERO_VALUE, TWO_VALUE, THREE_VALUE));

		checkValues(accuracy, ZERO_VALUE, TWO_VALUE, THREE_VALUE);

		checkTostring(accuracy, "0.002003");
	}

	[Fact]
	public void TestThreeTwoNull()
	{
		GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(THREE_VALUE, TWO_VALUE, null));

		checkValues(accuracy, THREE_VALUE, TWO_VALUE, ZERO_VALUE);

		checkTostring(accuracy, "3.002000");
	}

	[Fact]
	public void TestOneNullOne()
	{
		GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ONE_VALUE, null, ONE_VALUE));

		checkValues(accuracy, ONE_VALUE, ZERO_VALUE, ONE_VALUE);

		checkTostring(accuracy, "1.000001");
	}

	[Fact]
	public void TestZeroNullNull()
	{
		GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ZERO_VALUE, null, null));

		checkValues(accuracy, ZERO_VALUE, ZERO_VALUE, ZERO_VALUE);

		checkTostring(accuracy, "0.000000");
	}

	[Fact]
	public void TestNullNullNull()
	{
		GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(null, null, null));

		checkValues(accuracy, ZERO_VALUE, ZERO_VALUE, ZERO_VALUE);

		checkTostring(accuracy, "0.000000");
	}

	private void checkValues(
		GenTimeAccuracy accuracy,
		DerInteger      secs,
		DerInteger      millis,
		DerInteger      micros)
	{
		Assert.Equal(secs.Value.IntValue, accuracy.Seconds);
		Assert.Equal(millis.Value.IntValue, accuracy.Millis);
		Assert.Equal(micros.Value.IntValue, accuracy.Micros);
	}

	private void checkTostring(
		GenTimeAccuracy	accuracy,
		string			expected)
	{
		Assert.Equal(expected, accuracy.ToString());
	}
}
