// <copyright file="ThreadsDontMatter.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;

using System.Security.Cryptography;
using System.Text;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;
using Xunit.Abstractions;

/// <summary>
/// Checks that changing the number of threads in the config does not change the results.
/// </summary>
public static class ThreadsDontMatter
{
    /// <summary>
    /// Test <see cref="Argon2"/>.
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>
    /// The result text.
    /// </returns>
    public static (bool Passed, string Message) Test(ITestOutputHelper output)
    {
        const string password = "password1";
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

        // One random salt for all: a config without one draws its own random
        // salt, which would make the hashes differ for a reason unrelated to
        // threads.
        byte[] salt = RandomNumberGenerator.GetBytes(16);

        // (type, memory cost, time cost, lanes, threads to compare with one thread)
        var cases = new (Argon2Type Type, int MemoryCost, int TimeCost, int Lanes, int Threads)[]
        {
            (Argon2Type.DataIndependentAddressing, 32, 3, 4, 3),
            (Argon2Type.DataIndependentAddressing, 1024, 2, 4, 4),
            (Argon2Type.DataDependentAddressing, 1024, 2, 4, 4),
            (Argon2Type.DataDependentAddressing, 1024, 2, 8, 3),
            (Argon2Type.HybridAddressing, 1024, 2, 4, 4),
            (Argon2Type.HybridAddressing, 2048, 1, 8, 8),
        };

        var failures = new List<string>();
        foreach ((Argon2Type type, int memoryCost, int timeCost, int lanes, int threads) in cases)
        {
            string many = HashText(threads);
            string one = HashText(1);
            if (string.CompareOrdinal(many, one) != 0)
            {
                failures.Add($"{type} m={memoryCost} t={timeCost} p={lanes}: {threads} threads gave {many}, 1 thread gave {one}");
            }

            string HashText(int threadCount)
            {
                var config = new Argon2Config
                {
                    Type = type,
                    Version = Argon2Version.Nineteen,
                    Password = passwordBytes,
                    Salt = salt,
                    TimeCost = timeCost,
                    MemoryCost = memoryCost,
                    Lanes = lanes,
                    Threads = threadCount,
                };
                using var argon2 = new Argon2(config);
                return config.EncodeString(argon2.Hash());
            }
        }

        foreach (string failure in failures)
        {
            output.WriteLine(failure);
        }

        return failures.Count == 0
            ? (true, $"ThreadsDontMatter Passed ({cases.Length} cases)")
            : (false, $"ThreadsDontMatter FAILED: {string.Join("; ", failures)}");
    }
}
