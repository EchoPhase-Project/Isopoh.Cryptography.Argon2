// <copyright file="SecureArrayTests.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Test;

using System;
using System.Runtime.InteropServices;
using Isopoh.Cryptography.SecureArray;
using Xunit;

/// <summary>
/// <see cref="SecureArray{T}"/> protection levels, zeroing and lock failures, the
/// latter through a <see cref="SecureArrayCall"/> that refuses to lock above a size.
/// </summary>
public class SecureArrayTests
{
    /// <summary>
    /// Each protection type is what was asked for, and disposing zeroes the buffer.
    /// </summary>
    [Fact]
    public void ProtectionTypesAndZeroOnDispose()
    {
        var call = new FakeCall(lockLimit: int.MaxValue);
        using (var zeroed = new SecureArray<int>(4, SecureArrayType.Zeroed, call))
        {
            Assert.Equal(SecureArrayType.Zeroed, zeroed.ProtectionType);
        }

        var pinned = new SecureArray<ulong>(4, SecureArrayType.ZeroedAndPinned, call);
        Assert.Equal(SecureArrayType.ZeroedAndPinned, pinned.ProtectionType);
        pinned[1] = 42;
        Assert.Equal(42UL, pinned[1]);
        pinned.Dispose();
        Assert.Equal(0UL, pinned.Buffer[1]);

        var locked = new SecureArray<byte>(16, call);
        Assert.Equal(SecureArrayType.ZeroedPinnedAndNoSwap, locked.ProtectionType);
        Assert.Same(call, locked.Call);
        locked.Dispose();
        Assert.Equal(1, call.Locks);
        Assert.Equal(1, call.Unlocks);
    }

    /// <summary>
    /// Create and Best fall back to a pinned array when locking fails; NoSwap does not.
    /// </summary>
    [Fact]
    public void LockFailureFallsBackOrThrows()
    {
        var call = new FakeCall(lockLimit: 8);
        using (var best = SecureArray<byte>.Best(64, call))
        {
            Assert.Equal(SecureArrayType.ZeroedAndPinned, best.ProtectionType);
        }

        using (var bestEffort = SecureArray<byte>.Create(64, call))
        {
            Assert.Equal(SecureArrayType.ZeroedAndPinned, bestEffort.ProtectionType);
        }

        using (var none = SecureArray<byte>.Create(64, call, LockMemoryPolicy.None))
        {
            Assert.Equal(SecureArrayType.ZeroedAndPinned, none.ProtectionType);
        }

        using (var small = SecureArray<byte>.Create(4, call, (LockMemoryPolicy)99))
        {
            Assert.Equal(SecureArrayType.ZeroedPinnedAndNoSwap, small.ProtectionType);
        }

        var ex = Assert.Throws<LockFailException>(() => new SecureArray<byte>(64, SecureArrayType.ZeroedPinnedAndNoSwap, call));
        Assert.Contains("ReportMaxLockableOnLockFail", ex.Message);
        Assert.Contains("fake: over the limit", ex.Message);

        var unsupported = new FakeCall(lockLimit: int.MaxValue, supported: false);
        Assert.Throws<LockFailException>(() => new SecureArray<byte>(4, unsupported));
    }

    /// <summary>
    /// With ReportMaxLockableOnLockFail the message says how much could be locked.
    /// </summary>
    [Fact]
    public void LockFailureReportsMaximum()
    {
        bool previous = SecureArray.ReportMaxLockableOnLockFail;
        SecureArray.ReportMaxLockableOnLockFail = true;
        try
        {
            var call = new FakeCall(lockLimit: 1000);
            var ex = Assert.Throws<LockFailException>(() => new SecureArray<byte>(4000, call));

            // The search for the maximum stops within a byte of it.
            Assert.Matches(@"Currently available: (999|1000) bytes", ex.Message);
        }
        finally
        {
            SecureArray.ReportMaxLockableOnLockFail = previous;
        }
    }

    /// <summary>
    /// Zero for arrays and spans of each built-in type, and the error for others.
    /// </summary>
    [Fact]
    public void ZeroAndElementSizes()
    {
        var call = new FakeCall(lockLimit: int.MaxValue);
        var longs = new long[] { 1, 2, 3 };
        SecureArray.Zero(longs, call);
        Assert.Equal(new long[3], longs);
        var doubles = new double[] { 1.5, 2.5 };
        SecureArray.Zero(doubles.AsSpan(), call);
        Assert.Equal(new double[2], doubles);
        var bytes = new byte[] { 9, 9 };
        SecureArray.Zero(bytes);
        Assert.Equal(new byte[2], bytes);
        var chars = new[] { 'a', 'b' };
        SecureArray.Zero(chars.AsSpan());
        Assert.Equal(new char[2], chars);

        Assert.Equal(16, SecureArray.BuiltInTypeElementSize(new decimal[1]));
        Assert.Equal(1, SecureArray.BuiltInTypeElementSize(new bool[1].AsSpan()));
        Assert.Throws<NotSupportedException>(() => SecureArray.BuiltInTypeElementSize(new DateTime[1]));
        Assert.Throws<NotSupportedException>(() => SecureArray.BuiltInTypeElementSize(new Guid[1].AsSpan()));
        Assert.Throws<ArgumentNullException>(() => SecureArray.Zero<int>(null!));
    }

    /// <summary>
    /// The constructors that take the default call, and zeroing an empty span.
    /// </summary>
    [Fact]
    public void DefaultCallConstructors()
    {
        using (var pinned = new SecureArray<byte>(8, SecureArrayType.ZeroedAndPinned))
        {
            Assert.Same(SecureArray.DefaultCall, pinned.Call);
        }

        try
        {
            using var locked = new SecureArray<byte>(8);
            Assert.Equal(SecureArrayType.ZeroedPinnedAndNoSwap, locked.ProtectionType);
        }
        catch (LockFailException)
        {
            // A machine may not allow locking even 8 bytes; the constructor still ran.
        }

        SecureArray.Zero(Span<int>.Empty);
    }

    /// <summary>
    /// The platform's default calls work on this machine.
    /// </summary>
    [Fact]
    public void DefaultCallWorks()
    {
        SecureArrayCall call = SecureArray.DefaultCall;
        Assert.False(string.IsNullOrEmpty(call.Os));
        call.Os = call.Os;
        using var array = SecureArray<byte>.Best(32, null);
        Assert.Same(call, array.Call);
        array.Call = call;
    }

    /// <summary>
    /// The exception's constructors.
    /// </summary>
    [Fact]
    public void LockFailExceptionConstructors()
    {
        Assert.NotNull(new LockFailException().Message);
        Assert.Equal("m", new LockFailException("m").Message);
        var inner = new InvalidOperationException();
        Assert.Same(inner, new LockFailException("m", inner).InnerException);
    }

    private sealed class FakeCall : SecureArrayCall
    {
        public FakeCall(long lockLimit, bool supported = true)
            : base(
                (m, l) => { },
                (m, l) => null,
                (m, l) => { },
                "Fake",
                supported)
        {
            this.ZeroMemory = (m, l) => Marshal.Copy(new byte[(int)l], 0, m, (int)l);
            this.LockMemory = (m, l) =>
            {
                if ((long)l > lockLimit)
                {
                    return "fake: over the limit";
                }

                this.Locks++;
                return null;
            };
            this.UnlockMemory = (m, l) => this.Unlocks++;
        }

        public int Locks { get; private set; }

        public int Unlocks { get; private set; }
    }
}
