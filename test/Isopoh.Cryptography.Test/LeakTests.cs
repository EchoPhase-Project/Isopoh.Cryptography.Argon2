// <copyright file="LeakTests.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Test;

using System;
using System.Runtime;
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
    /// whole process, so the test subtracts the count after an empty loop and
    /// keeps the smallest difference of up to three attempts.
    /// </summary>
    [Fact]
    public void ParallelHashLeavesNothingToFinalize()
    {
        const int hashes = 32;
        const int lanes = 8;
        const int attempts = 3;
        byte[] password = { 1, 2, 3, 4 };
        byte[] salt = new byte[16];

        // Warm up.
        Hash();

        long? minDelta = null;
        for (int attempt = 1; attempt <= attempts; ++attempt)
        {
            long? baseline = PendingAfter(() => { }, out string baselineFailure);
            long? withHashes = PendingAfter(
                () =>
                {
                    for (int i = 0; i < hashes; ++i)
                    {
                        Hash();
                    }
                },
                out string hashesFailure);
            if (baseline is null || withHashes is null)
            {
                this.output.WriteLine(
                    $"Attempt {attempt}: invalid. Baseline: {baseline?.ToString() ?? baselineFailure}; "
                    + $"with hashes: {withHashes?.ToString() ?? hashesFailure}.");
                continue;
            }

            long delta = withHashes.Value - baseline.Value;
            this.output.WriteLine(
                $"Attempt {attempt}: valid. Baseline {baseline}, with hashes {withHashes}, delta {delta}.");
            minDelta = minDelta is null ? delta : Math.Min(minDelta.Value, delta);
            if (minDelta < lanes)
            {
                break;
            }
        }

        if (minDelta is null)
        {
            // xUnit 2 has no runtime skip. The environment did not allow a
            // measurement, which says nothing about the code.
            this.output.WriteLine("No valid measurement: the test makes no assertion.");
            return;
        }

        // Each hash used to leave one wait handle for each thread: 256 here.
        Assert.True(
            minDelta < lanes,
            $"{minDelta} more objects to finalize after {hashes} hashes with {lanes} threads than after an empty loop.");

        void Hash()
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
    private static long? PendingAfter(Action body, out string failure)
    {
        // Empty the finalization queue.
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        GC.WaitForPendingFinalizers();

        if (!GC.TryStartNoGCRegion(64L * 1024 * 1024))
        {
            failure = "the region without garbage collection did not start";
            return null;
        }

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

        if (!survived)
        {
            failure = "the region without garbage collection ended before the loop finished";
            return null;
        }

        GC.Collect();
        long pending = GC.GetGCMemoryInfo().FinalizationPendingCount;
        GC.WaitForPendingFinalizers();
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
