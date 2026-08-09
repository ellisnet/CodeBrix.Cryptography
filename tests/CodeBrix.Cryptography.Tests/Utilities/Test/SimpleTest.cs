using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading;
using CodeBrix.Cryptography.Utilities.IO;
using Xunit;

namespace CodeBrix.Cryptography.Utilities.Test; //was previously: Org.BouncyCastle.Utilities.Test;

public abstract class SimpleTest
    : ITest
{
    // Upstream looked for a folder named "bc-test-data" by walking UP from the working
    // directory, which resolves to a separate ~4.6 GB repository that has to be cloned
    // beside the source tree. This fork keeps every fixture inside the repository, in
    // test-data/, and copies it next to the test assembly at build time. Resolving from
    // AppContext.BaseDirectory (rather than walking up) is deliberate: it means the
    // lookup can never climb out of the repository and silently pick up a checkout that
    // happens to be sitting next to it, which would make the suite pass on one machine
    // and fail on another.
    private static readonly string DataDirName = "test-data";

    internal static readonly string NewLine = Environment.NewLine;

    private static string m_testDataPath;

    public abstract string Name { get; }

    private ITestResult Success() => SimpleTestResult.Successful(this, "Okay");

    internal void Fail(string message) => throw new TestFailedException(SimpleTestResult.Failed(this, message));

    internal void Fail(string message, Exception throwable) =>
        throw new TestFailedException(SimpleTestResult.Failed(this, message, throwable));

    internal void Fail(string message, object expected, object found) =>
        throw new TestFailedException(SimpleTestResult.Failed(this, message, expected, found));

    internal void FailIf(string message, bool condition)
    {
        if (condition)
        {
            Fail(message);
        }
    }

    internal void IsTrue(bool value) => IsTrue("no message", value);

    internal void IsTrue(string message, bool value) => FailIf(message, !value);

    internal void IsEquals(bool a, bool b) => IsEquals("no message", a, b);

    internal void IsEquals(int a, int b) => IsEquals("no message", a, b);

    internal void IsEquals(long a, long b) => IsEquals("no message", a, b);

    internal void IsEquals(object a, object b) => IsEquals("no message", a, b);

    internal void IsEquals(string message, bool a, bool b) => FailIf(message, a != b);

    internal void IsEquals(string message, int a, int b) => FailIf(message, a != b);

    internal void IsEquals(string message, long a, long b) => FailIf(message, a != b);

    internal void IsEquals(string message, object a, object b) => FailIf(message, !Objects.Equals(a, b));

    public virtual ITestResult Perform()
    {
        try
        {
            PerformTest();

            return Success();
        }
        catch (TestFailedException e)
        {
            return e.Result;
        }
        catch (Exception e)
        {
            return SimpleTestResult.Failed(this, "Exception: " +  e, e);
        }
    }

    internal static bool AreEqual(byte[] a, byte[] b) => Arrays.AreEqual(a, b);

    internal static bool AreEqual(byte[] a, int aFromIndex, int aToIndex, byte[] b, int bFromIndex, int bToIndex) =>
        Arrays.AreEqual(a, aFromIndex, aToIndex, b, bFromIndex, bToIndex);

    internal static void RunTest(ITest test) => RunTest(test, Console.Out);

    internal static void RunTest(ITest test, TextWriter outStream)
    {
        ITestResult result = test.Perform();

        outStream.WriteLine(result.ToString());
        if (result.GetException() != null)
        {
            outStream.WriteLine(result.GetException().StackTrace);
        }
    }

    internal static byte[] GetTestData(string name) => Streams.ReadAll(GetTestDataAsStream(name));

    internal static Stream GetTestDataAsStream(string name) =>
        GetAssembly().GetManifestResourceStream(GetFullName(name));

    internal static string[] GetTestDataEntries(string prefix)
    {
        string fullPrefix = GetFullName(prefix);

        var result = new List<string>();
        string[] fullNames = GetAssembly().GetManifestResourceNames();
        foreach (string fullName in fullNames)
        {
            if (fullName.StartsWith(fullPrefix))
            {
                string name = GetShortName(fullName);
                result.Add(name);
            }
        }
        return result.ToArray();
    }

    private static Assembly GetAssembly() => typeof(SimpleTest).Assembly;

    private static string GetFullName(string name) => "CodeBrix.Cryptography.data." + name;

    private static string GetShortName(string fullName) => fullName.Substring("CodeBrix.Cryptography.data.".Length);

    public abstract void PerformTest();

    public static DateTime MakeUtcDateTime(int year, int month, int day, int hour, int minute, int second) =>
        new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc);

    public static DateTime MakeUtcDateTime(int year, int month, int day, int hour, int minute, int second,
        int millisecond)
    {
        return new DateTime(year, month, day, hour, minute, second, millisecond, DateTimeKind.Utc);
    }

    public static void TestBitStringConstant(int bitNo, int value)
    {
        int expectedValue = 1 << ((bitNo | 7) - (bitNo & 7));
        if (expectedValue != value)
            throw new ArgumentException("bit value " + bitNo + " wrong");
    }

    internal static TValue EnsureSingletonInitialized<TValue>(ref TValue value, Func<TValue> initialize)
        where TValue : class
    {
        TValue currentValue = Volatile.Read(ref value);
        if (null != currentValue)
            return currentValue;

        TValue candidateValue = initialize();

        return Interlocked.CompareExchange(ref value, candidateValue, null) ?? candidateValue;
    }

    private static string FindTestDataPath()
    {
        string dataDirPath = Path.Combine(AppContext.BaseDirectory, DataDirName);
        if (!Directory.Exists(dataDirPath))
        {
            throw new DirectoryNotFoundException("Test data directory not found: " + dataDirPath + NewLine +
                "It is copied from the repository's test-data/ folder at build time; a missing " +
                "directory means that copy did not happen.");
        }
        return dataDirPath;
    }

    internal static Stream FindTestResource(string path) =>
        File.OpenRead(ResolveTestResource(path));

    internal static Stream FindTestResource(string path1, string path2) =>
        File.OpenRead(ResolveTestResource(Path.Combine(path1, path2)));

    internal static Stream FindTestResource(string path1, string path2, string path3) =>
        File.OpenRead(ResolveTestResource(Path.Combine(path1, path2, path3)));

    /// <summary>
    /// Resolves a fixture against the repository's own test-data first, falling back to an
    /// external bc-test-data checkout only when that has been opted into.
    /// </summary>
    /// <remarks>
    /// Fixtures this repository owns always win, so the opt-in cannot change the outcome of
    /// a test that already passes; it only supplies the files this repository cannot
    /// redistribute. See BcTestData for the opt-in itself.
    /// </remarks>
    private static string ResolveTestResource(string relativePath)
    {
        string path = Path.Combine(GetTestDataPath(), relativePath);
        if (File.Exists(path))
            return path;

        string external = BcTestData.ResolveOptionalResource(relativePath);
        return external ?? path;
    }

    private static string GetTestDataPath() => EnsureSingletonInitialized(ref m_testDataPath, FindTestDataPath);
}
