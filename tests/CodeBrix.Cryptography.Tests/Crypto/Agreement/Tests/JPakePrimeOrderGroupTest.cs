using System;
using CodeBrix.Cryptography.Crypto.Agreement.JPake;
using CodeBrix.Cryptography.Math;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Crypto.Agreement.Tests; //was previously: Org.BouncyCastle.Crypto.Agreement.Tests;

public class JPakePrimeOrderGroupTest
    : SimpleTest
{
    public override void PerformTest()
    {
        TestConstruction();
    }

    public override string Name
    {
        get { return "JPakePrimeOrderGroup"; }
    }

    [Fact]
    public void TestFunction()
    {
        string resultText = Perform().ToString();

        Assert.Equal(Name + ": Okay", resultText);
    }

    internal void TestConstruction()
    {
        // p-1 not evenly divisible by q
        try
        {
            new JPakePrimeOrderGroup(BigInteger.Seven, BigInteger.Five, BigInteger.Six);

            Fail("failed to throw exception on p-1 not evenly divisible by q");
        }
        catch (ArgumentException)
        {
            // expected
        }

        // g < 2
        try
        {
            new JPakePrimeOrderGroup(BigInteger.ValueOf(11), BigInteger.Five, BigInteger.One);

            Fail("failed to throw exception on g < 2");
        }
        catch (ArgumentException)
        {
            // expected
        }

        // g > p - 1
        try
        {
            new JPakePrimeOrderGroup(BigInteger.ValueOf(11), BigInteger.Five, BigInteger.ValueOf(11));

            Fail("failed to throw exception on g > p - 1");
        }
        catch (ArgumentException)
        {
            // expected
        }

        //g^q mod p not equal 1
        try
        {
            new JPakePrimeOrderGroup(BigInteger.ValueOf(11), BigInteger.Five, BigInteger.Six);

            Fail("failed to throw exception on g^q mod p not equal 1");
        }
        catch (ArgumentException)
        {
            // expected
        }

        // p not prime
        try
        {
            new JPakePrimeOrderGroup(BigInteger.ValueOf(15), BigInteger.Two, BigInteger.Four);

            Fail("failed to throw exception on p not prime");
        }
        catch (ArgumentException)
        {
            // expected
        }

        // q not prime
        try
        {
            new JPakePrimeOrderGroup(BigInteger.Seven, BigInteger.Six, BigInteger.Three);

            Fail("failed to throw exception on q not prime");
        }
        catch (ArgumentException)
        {
            // expected
        }

        // should succeed
        new JPakePrimeOrderGroup(BigInteger.Seven, BigInteger.Three, BigInteger.Four);
    }
}
