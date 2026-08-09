using System;
using Xunit;

namespace CodeBrix.Cryptography.Utilities.Test; //was previously: Org.BouncyCastle.Utilities.Test;

public class TestFailedException
    : Exception
{
    private readonly ITestResult m_result;

    public TestFailedException(ITestResult result)
        : base()
    {
        m_result = result;
    }

    public ITestResult Result => m_result;
}
