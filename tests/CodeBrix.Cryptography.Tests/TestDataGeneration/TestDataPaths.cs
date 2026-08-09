using System;
using System.IO;

namespace CodeBrix.Cryptography.TestDataGeneration;

/// <summary>
/// Locates the repository's test-data folder for the regeneration utilities.
/// </summary>
/// <remarks>
/// This walks up from the build output to find the repository root, which is exactly what
/// SimpleTest deliberately does NOT do at test time. The distinction matters: the test-time
/// lookup must never be able to climb out of the repository, whereas these utilities are
/// run by a developer against a working tree and have to write back into it.
/// </remarks>
internal static class TestDataPaths
{
    private const string SolutionFileName = "CodeBrix.Cryptography.slnx";

    internal static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir.FullName, SolutionFileName)))
                return dir.FullName;

            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException(
            "Could not locate the repository root (no " + SolutionFileName + " above " +
            AppContext.BaseDirectory + ").");
    }

    internal static string RepositoryTestDataRoot()
    {
        string path = Path.Combine(RepositoryRoot(), "test-data");
        Directory.CreateDirectory(path);
        return path;
    }
}
