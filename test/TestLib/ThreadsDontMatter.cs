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

        // One random salt for both: a config without one draws its own random
        // salt, which would make the hashes differ for a reason unrelated to
        // threads.
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        var configA = new Argon2Config
        {
            Type = Argon2Type.DataIndependentAddressing,
            Version = Argon2Version.Nineteen,
            Password = passwordBytes,
            Salt = salt,
            TimeCost = 3,
            MemoryCost = 32,
            Lanes = 4,
            Threads = 3,
        };

        var configB = new Argon2Config
        {
            Type = Argon2Type.DataIndependentAddressing,
            Version = Argon2Version.Nineteen,
            Password = passwordBytes,
            Salt = salt,
            TimeCost = 3,
            MemoryCost = 32,
            Lanes = 4,
            Threads = 1,
        };
        using var argon2A = new Argon2(configA);
        using var argon2B = new Argon2(configB);
        Span<byte> hashA = argon2A.Hash();
        Span<byte> hashB = argon2B.Hash();
        string hashTextA = configA.EncodeString(hashA);
        string hashTextB = configB.EncodeString(hashB);
        bool res = string.Compare(hashTextA, hashTextB, StringComparison.Ordinal) == 0;
        string resText = res
            ? "ThreadsDontMatter Passed"
            : "ThreadsDontMatter FAILED";
        return (res, resText);
    }
}
