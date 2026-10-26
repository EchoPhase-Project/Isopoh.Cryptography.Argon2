// <copyright file="LeakTests.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Test;

using System;
using System.Runtime;
using System.Threading;
using Isopoh.Cryptography.Argon2;
using TestLib;
using Xunit;
using Xunit.Abstractions;

/// <summary>
/// Leak checks: managed heap growth, objects that are not collected, and
/// memory locks that are not released. The heap measurement covers the whole
/// process, so these run in a collection that runs alone (after the parallel
/// tests), not at the same time as other tests.
/// </summary>
[Collection(LeakTestCollection.Name)]
public class LeakTests
{
    /// <summary>
    /// The allocation budget of a region without garbage collection.
    /// </summary>
    private const long NoGCBudget = 64L * 1024 * 1024;

    private readonly ITestOutputHelper output;

    /// <summary>
    /// Initializes a new instance of the <see cref="LeakTests"/> class.
    /// </summary>
    /// <param name="output">Where to send the output.</param>
    public LeakTests(ITestOutputHelper output)
    {
        this.output = output;
    }

    /// <summary>
    /// Test <see cref="Argon2.Verify(string, string, Isopoh.Cryptography.SecureArray.SecureArrayCall)"/> for leaks.
    /// </summary>
    [Fact]
    public void TestLeakInVerify()
    {
        (bool passed, string text) = LeakInVerify.Test(this.output);
        Assert.True(passed, text);
    }

    /// <summary>
    /// Test <see cref="Argon2.Hash(Argon2Config)"/> for leaks.
    /// </summary>
    [Fact]
    public void TestLeakInHash()
    {
        (bool passed, string text) = LeakInHash.Test(this.output);
        Assert.True(passed, text);
    }

    /// <summary>
    /// A hash with more than one thread leaves no objects for the finalizer,
    /// such as wait handles that it did not dispose. With no garbage
    /// collection during the hashes, one forced collection afterwards finds
    /// every object that needs finalization. The finalization queue covers the
    /// whole process, and a batch of parallel work can have a constant cost
    /// that is not a leak (on CI, the same 8 runtime objects after 32 or 64
    /// hashes). Thus the test compares a batch of 32 hashes with a batch of
    /// 64 hashes. A leak grows with the count of hashes, and a constant cost
    /// for each batch cancels. The test keeps the smallest growth of up to
    /// three attempts.
    /// </summary>
    [Fact]
    public void ParallelHashLeavesNothingToFinalize()
    {
        const int hashes = 32;
        const int lanes = 8;
        const int attempts = 3;
        byte[] password = { 1, 2, 3, 4 };
        byte[] salt = new byte[16];

        // Warm up with the same loop that the test measures.
        Hashes(hashes);

        long? minGrowth = null;
        for (int attempt = 1; attempt <= attempts; ++attempt)
        {
            long? baseline = this.PendingAfter(() => { }, out string baselineFailure);
            long? small = this.PendingAfter(() => Hashes(hashes), out string smallFailure);
            long? large = this.PendingAfter(() => Hashes(2 * hashes), out string largeFailure);
            string delta = baseline is null || small is null ? "unknown" : (small - baseline).ToString();
            if (small is null || large is null)
            {
                this.output.WriteLine(
                    $"Attempt {attempt}: invalid. {hashes} hashes: {small?.ToString() ?? smallFailure}; "
                    + $"{2 * hashes} hashes: {large?.ToString() ?? largeFailure}; "
                    + $"empty loop: {baseline?.ToString() ?? baselineFailure}.");
                continue;
            }

            long growth = large.Value - small.Value;
            this.output.WriteLine(
                $"Attempt {attempt}: valid. {hashes} hashes {small}, {2 * hashes} hashes {large}, growth {growth}; "
                + $"empty loop {baseline?.ToString() ?? baselineFailure}, delta to {hashes} hashes {delta}.");
            minGrowth = minGrowth is null ? growth : Math.Min(minGrowth.Value, growth);
            if (minGrowth < lanes)
            {
                break;
            }
        }

        if (minGrowth is null)
        {
            // xUnit 2 has no runtime skip. The environment did not allow a
            // measurement, which says nothing about the code.
            this.output.WriteLine("No valid measurement: the test makes no assertion.");
            return;
        }

        // Each hash used to leave one wait handle for each thread: 256 more
        // for the larger batch.
        Assert.True(
            minGrowth < lanes,
            $"{minGrowth} more objects to finalize after {2 * hashes} hashes than after {hashes} hashes, with {lanes} threads.");

        void Hashes(int count)
        {
            for (int i = 0; i < count; ++i)
            {
                var config = new Argon2Config
                {
                    Type = Argon2Type.HybridAddressing,
                    TimeCost = 1,
                    MemoryCost = 64,
                    Lanes = lanes,
                    Threads = lanes,
                    Password = password,
                    Salt = salt,
                };
                using var argon2 = new Argon2(config);
                _ = argon2.Hash();
            }
        }
    }

    /// <summary>
    /// Count the objects that wait for finalization after <paramref name="body"/>
    /// runs with no garbage collection.
    /// </summary>
    /// <param name="body">The work to measure.</param>
    /// <param name="failure">Why the measurement is not valid, or empty.</param>
    /// <returns>
    /// The count, or null if the region without garbage collection did not
    /// hold for all of <paramref name="body"/>.
    /// </returns>
    private long? PendingAfter(Action body, out string failure)
    {
        // Empty the finalization queue.
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        GC.WaitForPendingFinalizers();

        if (!GC.TryStartNoGCRegion(NoGCBudget))
        {
            failure = "the region without garbage collection did not start";
            return null;
        }

        int threadsBefore = ThreadPool.ThreadCount;
        long allocatedBefore = GC.GetTotalAllocatedBytes(true);
        bool survived;
        try
        {
            body();
        }
        finally
        {
            survived = GCSettings.LatencyMode == GCLatencyMode.NoGCRegion;
            if (survived)
            {
                GC.EndNoGCRegion();
            }
        }

        long allocated = GC.GetTotalAllocatedBytes(true) - allocatedBefore;
        int threadsAfter = ThreadPool.ThreadCount;
        if (!survived)
        {
            failure = "the region without garbage collection ended before the loop finished";
            return null;
        }

        GC.Collect();
        long pending = GC.GetGCMemoryInfo().FinalizationPendingCount;
        GC.WaitForPendingFinalizers();
        this.output.WriteLine(
            $"  Pending {pending}; allocated {allocated / 1024} KiB of {NoGCBudget / 1024} KiB; "
            + $"pool threads {threadsBefore} -> {threadsAfter}.");
        failure = string.Empty;
        return pending;
    }
}

/// <summary>
/// The collection of <see cref="LeakTests"/>: xUnit runs it without other tests at the same time.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
#pragma warning disable SA1402 // the definition belongs with its tests.
public class LeakTestCollection
#pragma warning restore SA1402
{
    /// <summary>
    /// The name of the collection.
    /// </summary>
    public const string Name = "Leak tests";
}
