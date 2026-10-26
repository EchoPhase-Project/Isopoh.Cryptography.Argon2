// <copyright file="LeakInHash.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;

using System.Text;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;
using Xunit.Abstractions;

/// <summary>
/// Look for leaks.
/// </summary>
public static class LeakInHash
{
    /// <summary>
    /// Look for leaks of managed memory, of objects, and of memory locks in hashing.
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>String with pass/fail message.</returns>
    public static (bool Passed, string Message) Test(ITestOutputHelper output)
    {
        var tracker = new LockTracker();
        var config = new Argon2Config
        {
            Password = Encoding.UTF8.GetBytes("b"),
            Salt = Encoding.UTF8.GetBytes("somesaltsomesalt"),
            MemoryCost = 1024,
            TimeCost = 2,
            Lanes = 2,
            Threads = 2,
            SecureArrayCall = tracker.Call,
        };

        (long perIteration, long[] windowGrowth, string? leak) = MemoryGrowth.Measure(() => Argon2.Hash(config));
        output.WriteLine($"TestHashLeaks: {perIteration} bytes per iteration (median); window growth [{string.Join(", ", windowGrowth)}].");

        string? notCollected = MemoryGrowth.NotCollected(() =>
        {
            var argon2 = new Argon2(config);
            argon2.Hash();
            argon2.Dispose();
            var memory = new Argon2Memory(config, Argon2MemoryPolicy.NoShrink, LockMemoryPolicy.BestEffort);
            Argon2.Hash(memory);
            memory.Dispose();
            return new[] { ("Argon2", new WeakReference(argon2)), ("Argon2Memory", new WeakReference(memory)) };
        });

        var errs = new List<string>();
        if (leak != null)
        {
            errs.Add(leak);
        }

        if (notCollected != null)
        {
            errs.Add(notCollected);
        }

        errs.AddRange(tracker.Errors());
        string? failedLocks = tracker.FailedLocks();
        return (!errs.Any(), errs.Any() ? $"Hash leaks: FAILED: {string.Join(" ", errs)}{(failedLocks == null ? string.Empty : $" {failedLocks}")}" : "Hash leaks: Passed");
    }
}
