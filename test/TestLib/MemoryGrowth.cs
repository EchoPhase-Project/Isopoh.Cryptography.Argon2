// <copyright file="MemoryGrowth.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;

using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Decide whether per-iteration managed heap growth is a leak.
/// </summary>
/// <remarks>
/// <see cref="GC.GetTotalMemory(bool)"/> measures the whole process, so a
/// test runner (xUnit, VSTest) that allocates a few bytes while an iteration
/// runs shows up as growth even when the code under test frees everything.
/// Argon2 works in 1 KiB blocks, so anything it leaks is at least that big.
/// </remarks>
public static class MemoryGrowth
{
    /// <summary>
    /// Growth per iteration at or below this many bytes is noise, not a leak.
    /// </summary>
    public const long ThresholdBytes = 1024;

    /// <summary>
    /// Check the managed heap growth of each iteration.
    /// </summary>
    /// <param name="memoryDiff">Bytes the heap grew by in each iteration.</param>
    /// <returns>
    /// A failure message if every iteration grew by more than
    /// <see cref="ThresholdBytes"/>; otherwise null.
    /// </returns>
    public static string? Leak(IReadOnlyCollection<long> memoryDiff)
    {
        return memoryDiff.All(v => v > ThresholdBytes)
            ? $"Leaked {memoryDiff.Min()} bytes (more than {ThresholdBytes} in every iteration). [{string.Join(", ", memoryDiff)}]."
            : null;
    }
}
