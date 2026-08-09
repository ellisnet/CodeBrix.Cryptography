using System;

/*
 Basic test interface
 */
namespace CodeBrix.Cryptography.Utilities.Test; //was previously: Org.BouncyCastle.Utilities.Test;

public interface ITest
{
    string Name { get; }

    ITestResult Perform();
}
