using System;
using CodeBrix.Cryptography.Math;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Asn1.Cmp.Tests; //was previously: Org.BouncyCastle.Asn1.Cmp.Tests;

public class PollReqContentTest
    : SimpleTest
{
    public override string Name => "PollReqContentTest";

    public override void PerformTest()
    {
        BigInteger one = BigInteger.One, two = BigInteger.Two;
        BigInteger[] ids = { one, two };

        PollReqContent c = new PollReqContent(ids);

        DerInteger[][] vs = c.GetCertReqIDs();

        IsTrue(vs.Length == 2);
        for (int i = 0; i != vs.Length; i++)
        {
            IsTrue(vs[i].Length == 1);
            IsTrue(vs[i][0].Value.Equals(ids[i]));
        }

        BigInteger[] values = c.GetCertReqIDValues();

        IsTrue(values.Length == 2);
        for (int i = 0; i != values.Length; i++)
        {
            IsTrue(values[i].Equals(ids[i]));
        }

        c = new PollReqContent(two);
        vs = c.GetCertReqIDs();

        IsTrue(vs.Length == 1);

        IsTrue(vs[0].Length == 1);
        IsTrue(vs[0][0].Value.Equals(two));
    }

    [Fact]
    public void TestFunction()
    {
        string resultText = Perform().ToString();

        Assert.Equal(Name + ": Okay", resultText);
    }
}
