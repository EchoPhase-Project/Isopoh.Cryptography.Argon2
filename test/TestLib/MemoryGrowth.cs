// <copyright file="MemoryGrowth.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;

using System.Runtime.CompilerServices;

/// <summary>
/// Decide whether repeated calls leak managed memory.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Measure"/> runs some warm-up iterations (to fill caches, the
/// thread pool, and lock-tracking dictionaries), then measures the settled
/// heap growth over <see cref="Windows"/> windows of
/// <see cref="WindowIterations"/> iterations each. The median window,
/// divided by its iteration count, is compared against a small threshold. A
/// leak of more than <see cref="ThresholdBytes"/> per call on average, even
/// an intermittent one, shows in every window and so in the median. A
/// one-off jump of the process (a per-thread cache such as ArrayPool, a new
/// thread-pool thread, a test runner allocation) shows in one window only,
/// and the median ignores it.
/// </para>
/// <para>
/// <see cref="GC.GetTotalMemory(bool)"/> measures the whole process: run
/// these checks where nothing else allocates at the same time (in xUnit, a
/// collection with parallelization disabled) and do not write test output in
/// the measured loop (xUnit keeps that output in memory).
/// </para>
/// </remarks>
public static class MemoryGrowth
{
    /// <summary>
    /// Average growth per iteration at or below this many bytes is noise, not a leak.
    /// </summary>
    public const long ThresholdBytes = 64;

    /// <summary>
    /// Iterations run before the measurement starts.
    /// </summary>
    public const int WarmUpIterations = 5;

    /// <summary>
    /// The number of measured windows.
    /// </summary>
    public const int Windows = 5;

    /// <summary>
    /// Iterations in each measured window.
    /// </summary>
    public const int WindowIterations = 32;

    /// <summary>
    /// Measure the settled-heap growth of <paramref name="iteration"/>.
    /// </summary>
    /// <param name="iteration">The work to repeat.</param>
    /// <returns>
    /// The median growth per iteration, the growth of each window, and a
    /// failure message if the median is more than <see cref="ThresholdBytes"/>
    /// per iteration (otherwise null).
    /// </returns>
    public static (long PerIteration, long[] WindowGrowth, string? Leak) Measure(Action iteration)
    {
        for (var i = 0; i < WarmUpIterations; ++i)
        {
            iteration();
        }

        var windowGrowth = new long[Windows];
        long before = SettledHeap();
        for (var w = 0; w < Windows; ++w)
        {
            for (var i = 0; i < WindowIterations; ++i)
            {
                iteration();
            }

            long after = SettledHeap();
            windowGrowth[w] = after - before;
            before = after;
        }

        long median = windowGrowth.OrderBy(g => g).ElementAt(Windows / 2);
        long perIteration = median / WindowIterations;
        return (
            perIteration,
            windowGrowth,
            perIteration > ThresholdBytes
                ? $"Leaked {perIteration} bytes per iteration (median of {Windows} windows of {WindowIterations} iterations; more than {ThresholdBytes}). Window growth: [{string.Join(", ", windowGrowth)}]."
                : null);
    }
    /// <summary>
    /// Check that the objects <paramref name="use"/> created are garbage
    /// collected once it returns.
    /// </summary>
    /// <param name="use">
    /// Creates, uses, and disposes objects, and returns a weak reference to
    /// each. It runs in a method of its own, so that no local of the caller
    /// keeps the objects alive.
    /// </param>
    /// <returns>A failure message if any object is still alive; otherwise null.</returns>
    public static string? NotCollected(Func<IReadOnlyList<(string Name, WeakReference Reference)>> use)
    {
        IReadOnlyList<(string Name, WeakReference Reference)> references = Run(use);
        for (var i = 0; i < 3 && references.Any(r => r.Reference.IsAlive); ++i)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }

        string[] alive = references.Where(r => r.Reference.IsAlive).Select(r => r.Name).ToArray();
        return alive.Length == 0 ? null : $"Not garbage collected after use: {string.Join(", ", alive)}.";

        [MethodImpl(MethodImplOptions.NoInlining)]
        static IReadOnlyList<(string Name, WeakReference Reference)> Run(Func<IReadOnlyList<(string Name, WeakReference Reference)>> use) => use();
    }

    private static long SettledHeap()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        return GC.GetTotalMemory(true);
    }
}
