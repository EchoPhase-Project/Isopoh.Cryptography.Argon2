// <copyright file="LeakInVerify.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;

using System.Collections.Generic;
using System.Linq;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;
using Xunit.Abstractions;

/// <summary>
/// Look for leaks.
/// </summary>
public static class LeakInVerify
{
    /// <summary>
    /// Look for leaks of managed memory, of objects, and of memory locks in verification.
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>String with pass/fail message.</returns>
    public static (bool Passed, string Message) Test(ITestOutputHelper output)
    {
        var tracker = new LockTracker();

        // From the reference implementation: argon2 somesaltsomesalt -i -x b -t 2 -k 1024 -p 2 -e
        const string hashString = "$argon2i$v=19$m=1024,t=2,p=2$c29tZXNhbHRzb21lc2FsdA$WNrZxo1Vhq48WiCMb14iQ5XWTNlGdxLED6oR+DqRaxw";
        const string password = "b";
        var verified = true;
        (long perIteration, long[] windowGrowth, string? leak) = MemoryGrowth.Measure(() => verified &= Argon2.Verify(hashString, password, tracker.Call));
        output.WriteLine($"TestVerifyLeaks: {perIteration} bytes per iteration (median); window growth [{string.Join(", ", windowGrowth)}].");

        string? notCollected = MemoryGrowth.NotCollected(() =>
        {
            var memory = new Argon2Memory(
                new Argon2Config { Password = Array.Empty<byte>(), SecureArrayCall = tracker.Call },
                Argon2MemoryPolicy.NoShrink,
                LockMemoryPolicy.BestEffort);
            memory.Reset(hashString, new Argon2Password(System.Text.Encoding.UTF8.GetBytes(password)));
            verified &= Argon2.Verify(hashString, memory);
            memory.Dispose();
            return new[] { ("Argon2Memory", new WeakReference(memory)) };
        });

        var errs = new List<string>();
        if (!verified)
        {
            errs.Add("A verification failed.");
        }

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
        return (!errs.Any(), errs.Any() ? $"Verify leaks: FAILED: {string.Join(" ", errs)}{(failedLocks == null ? string.Empty : $" {failedLocks}")}" : "Verify leaks: Passed");
    }
}
