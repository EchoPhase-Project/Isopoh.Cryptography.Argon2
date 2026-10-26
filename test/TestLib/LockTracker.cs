// <copyright file="LockTracker.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;

using Isopoh.Cryptography.SecureArray;

/// <summary>
/// A <see cref="SecureArrayCall"/> that wraps <see cref="SecureArray.DefaultCall"/>
/// and records each lock and unlock, to find locks that are never released
/// and unlocks of memory that was never locked.
/// </summary>
/// <remarks>
/// Only counts and a few examples are stored, so the tracker itself does not
/// grow while a leak check measures the heap.
/// </remarks>
public sealed class LockTracker
{
    private const int MaxExamples = 8;

    private readonly Dictionary<IntPtr, (UIntPtr Size, int Index)> locks = new(64);

    private readonly List<(IntPtr Address, UIntPtr Size)> failedLockExamples = new(MaxExamples);

    private int lockCount;

    private int failedLockCount;

    private int badLockCount;

    private int badUnlockCount;

    /// <summary>
    /// Initializes a new instance of the <see cref="LockTracker"/> class.
    /// </summary>
    public LockTracker()
    {
        this.Call = new SecureArrayCall(
            SecureArray.DefaultCall.ZeroMemory,
            this.Lock,
            this.Unlock,
            $"Wrapped {SecureArray.DefaultCall.Os}");
    }

    /// <summary>
    /// Gets the call to give to the code under test.
    /// </summary>
    public SecureArrayCall Call { get; }

    /// <summary>
    /// Gets the errors found so far: locks that are still held, double locks, and bad unlocks.
    /// </summary>
    /// <returns>The error messages; empty if none.</returns>
    public List<string> Errors()
    {
        var errs = new List<string>();
        lock (this.locks)
        {
            if (this.badLockCount > 0)
            {
                errs.Add($"{this.badLockCount} / {this.lockCount} locks of memory that was already locked.");
            }

            if (this.badUnlockCount > 0)
            {
                errs.Add($"{this.badUnlockCount} bad unlocks.");
            }

            if (this.locks.Count > 0)
            {
                errs.Add($"Leaked {this.locks.Count} / {this.lockCount} locks: address:size:index=[{string.Join(", ", this.locks.Take(MaxExamples).Select(kv => $"0x{kv.Key.ToInt64():x8}:{kv.Value.Size.ToUInt64()}:{kv.Value.Index}"))}].");
            }
        }

        return errs;
    }

    /// <summary>
    /// Gets a note on the locks that failed (memory that could not be locked
    /// against swapping, a limit of the machine, not an error of the code).
    /// </summary>
    /// <returns>The note, or null if no lock failed.</returns>
    public string? FailedLocks()
    {
        lock (this.locks)
        {
            if (this.failedLockCount == 0)
            {
                return null;
            }

            string s = this.failedLockCount > 1 ? "s" : string.Empty;
            return $"{this.failedLockCount} / {this.lockCount + this.failedLockCount} failed lock{s}, for example address:size=[{string.Join(", ", this.failedLockExamples.Select(x => $"0x{x.Address.ToInt64():x8}:{x.Size.ToUInt64()}"))}].";
        }
    }

    private string? Lock(IntPtr m, UIntPtr l)
    {
        string? ret = SecureArray.DefaultCall.LockMemory(m, l);
        lock (this.locks)
        {
            if (ret == null)
            {
                ++this.lockCount;
                if (!this.locks.TryAdd(m, (l, this.lockCount)))
                {
                    ++this.badLockCount;
                }
            }
            else
            {
                ++this.failedLockCount;
                if (this.failedLockExamples.Count < MaxExamples)
                {
                    this.failedLockExamples.Add((m, l));
                }
            }
        }

        return ret;
    }

    private void Unlock(IntPtr m, UIntPtr l)
    {
        lock (this.locks)
        {
            if (this.locks.Remove(m))
            {
                SecureArray.DefaultCall.UnlockMemory(m, l);
            }
            else
            {
                ++this.badUnlockCount;
            }
        }
    }
}
