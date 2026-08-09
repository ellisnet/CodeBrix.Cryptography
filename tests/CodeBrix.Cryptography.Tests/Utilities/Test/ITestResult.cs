using System;
using Xunit;

namespace CodeBrix.Cryptography.Utilities.Test; //was previously: Org.BouncyCastle.Utilities.Test;

public interface ITestResult
{
    bool IsSuccessful();

    Exception GetException();

    string ToString();
}
