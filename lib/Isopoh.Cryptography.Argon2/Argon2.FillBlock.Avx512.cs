// <copyright file="Argon2.FillBlock.Avx512.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

#if NET8_0_OR_GREATER
namespace Isopoh.Cryptography.Argon2;

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// AVX-512 version of the block fill: the AVX2 scheme with two rows (or
/// columns) per 512-bit register, A = (row r v0..v3 | row r+1 v0..v3) and so
/// on, so one vector G does the work of two; and two such registers per
/// iteration (four rows), to give the CPU independent chains. The diagonal
/// step rotates lanes within each 256-bit half (vpermq imm), the rotations
/// are vprorq.
/// </summary>
/// <remarks>
/// Each primitive falls back to portable Vector512 code when AVX-512F is
/// missing; the JIT drops the branch not taken. Hashing uses this kernel only
/// on AVX-512 hardware, but the portable code runs anywhere: the unit test
/// FillBlockKernelTests calls this kernel (and the AVX2 one) directly and
/// checks it against a scalar RFC 9106 block fill on every machine, through
/// the hardware path where AVX-512 is present.
/// </remarks>
public sealed partial class Argon2
{
    private static readonly Vector512<ulong> Low32Mask = Vector512.Create(0xFFFF_FFFFUL);

    // Lane indices for Permute4x64 within each 256-bit half (for the portable path).
    private static readonly Vector512<ulong> RotateOne = Vector512.Create(1UL, 2, 3, 0, 5, 6, 7, 4);
    private static readonly Vector512<ulong> RotateTwo = Vector512.Create(2UL, 3, 0, 1, 6, 7, 4, 5);
    private static readonly Vector512<ulong> RotateThree = Vector512.Create(3UL, 0, 1, 2, 7, 4, 5, 6);

    /// <summary>
    /// Gets a value indicating whether to use <see cref="FillBlockAvx512"/>: AVX-512F present and the
    /// runtime considers 512-bit vectors fast (it does not on Intel parts that
    /// slow their clock for them, unless DOTNET_PreferredVectorBitWidth=512).
    /// </summary>
    internal static bool UseAvx512 => Avx512F.IsSupported && Vector512.IsHardwareAccelerated;

    /// <summary>
    /// next = P(prev ^ ref) ^ (prev ^ ref) [^ next]; same contract as
    /// <see cref="FillBlockAvx2"/>.
    /// </summary>
    /// <param name="prev">The previous block.</param>
    /// <param name="refBlock">The reference block.</param>
    /// <param name="next">The block to fill; with <paramref name="withXor"/>, XORed over.</param>
    /// <param name="buf">Working buffer of 2 * <see cref="QwordsInBlock"/>.</param>
    /// <param name="withXor">XOR the result over <paramref name="next"/> (passes after the first).</param>
    internal static void FillBlockAvx512(ReadOnlySpan<ulong> prev, ReadOnlySpan<ulong> refBlock, Span<ulong> next, Span<ulong> buf, bool withXor)
    {
        if (prev.Length < QwordsInBlock || refBlock.Length < QwordsInBlock || next.Length < QwordsInBlock || buf.Length < 2 * QwordsInBlock)
        {
            throw new ArgumentException($"Expected blocks of {QwordsInBlock} qwords and a buffer of {2 * QwordsInBlock}.");
        }

        ref ulong p = ref MemoryMarshal.GetReference(prev);
        ref ulong f = ref MemoryMarshal.GetReference(refBlock);
        ref ulong n = ref MemoryMarshal.GetReference(next);

        // r: the block being permuted; x: what the result is XORed with at the end.
        ref ulong r = ref MemoryMarshal.GetReference(buf);
        ref ulong x = ref Unsafe.Add(ref r, QwordsInBlock);

        // Rows: four per iteration, rows (k, k+1) in one register set and
        // (k+2, k+3) in the other; a row is 16 words at 16 * row.
        for (nuint row = 0; row < QwordsInBlock; row += 64)
        {
            nuint s2 = row + 32;
            var a = LoadRows(ref f, ref p, ref n, ref x, row, withXor);
            var b = LoadRows(ref f, ref p, ref n, ref x, row + 4, withXor);
            var c = LoadRows(ref f, ref p, ref n, ref x, row + 8, withXor);
            var d = LoadRows(ref f, ref p, ref n, ref x, row + 12, withXor);
            var a2 = LoadRows(ref f, ref p, ref n, ref x, s2, withXor);
            var b2 = LoadRows(ref f, ref p, ref n, ref x, s2 + 4, withXor);
            var c2 = LoadRows(ref f, ref p, ref n, ref x, s2 + 8, withXor);
            var d2 = LoadRows(ref f, ref p, ref n, ref x, s2 + 12, withXor);

            Round512(ref a, ref b, ref c, ref d, ref a2, ref b2, ref c2, ref d2);

            StoreRows(a, ref r, row);
            StoreRows(b, ref r, row + 4);
            StoreRows(c, ref r, row + 8);
            StoreRows(d, ref r, row + 12);
            StoreRows(a2, ref r, s2);
            StoreRows(b2, ref r, s2 + 4);
            StoreRows(c2, ref r, s2 + 8);
            StoreRows(d2, ref r, s2 + 12);
        }

        // Columns: four per iteration, columns (k, k+1) and (k+2, k+3); column
        // k is the word pairs (2k, 2k+1) at strides of 16.
        for (nuint col = 0; col < 16; col += 8)
        {
            nuint c2o = col + 4;
            var a = LoadColumns(ref r, col);
            var b = LoadColumns(ref r, col + 32);
            var c = LoadColumns(ref r, col + 64);
            var d = LoadColumns(ref r, col + 96);
            var a2 = LoadColumns(ref r, c2o);
            var b2 = LoadColumns(ref r, c2o + 32);
            var c2 = LoadColumns(ref r, c2o + 64);
            var d2 = LoadColumns(ref r, c2o + 96);

            Round512(ref a, ref b, ref c, ref d, ref a2, ref b2, ref c2, ref d2);

            StoreColumnsXor(a, ref x, ref n, col);
            StoreColumnsXor(b, ref x, ref n, col + 32);
            StoreColumnsXor(c, ref x, ref n, col + 64);
            StoreColumnsXor(d, ref x, ref n, col + 96);
            StoreColumnsXor(a2, ref x, ref n, c2o);
            StoreColumnsXor(b2, ref x, ref n, c2o + 32);
            StoreColumnsXor(c2, ref x, ref n, c2o + 64);
            StoreColumnsXor(d2, ref x, ref n, c2o + 96);
        }
    }

    // Four words at offset of a row and the same four of the next row (+16),
    // read as prev ^ ref; x gets them [^ next] for the final XOR.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector512<ulong> LoadRows(ref ulong f, ref ulong p, ref ulong n, ref ulong x, nuint offset, bool withXor)
    {
        var low = Vector256.LoadUnsafe(ref f, offset) ^ Vector256.LoadUnsafe(ref p, offset);
        var high = Vector256.LoadUnsafe(ref f, offset + 16) ^ Vector256.LoadUnsafe(ref p, offset + 16);
        if (withXor)
        {
            (low ^ Vector256.LoadUnsafe(ref n, offset)).StoreUnsafe(ref x, offset);
            (high ^ Vector256.LoadUnsafe(ref n, offset + 16)).StoreUnsafe(ref x, offset + 16);
        }
        else
        {
            low.StoreUnsafe(ref x, offset);
            high.StoreUnsafe(ref x, offset + 16);
        }

        return Vector512.Create(low, high);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void StoreRows(Vector512<ulong> value, ref ulong destination, nuint offset)
    {
        value.GetLower().StoreUnsafe(ref destination, offset);
        value.GetUpper().StoreUnsafe(ref destination, offset + 16);
    }

    // Column k's four words of one quarter (pairs at offset and offset + 16)
    // in the low half, column k+1's (offset + 2) in the high half.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector512<ulong> LoadColumns(ref ulong r, nuint offset)
        => Vector512.Create(
            Vector256.Create(Vector128.LoadUnsafe(ref r, offset), Vector128.LoadUnsafe(ref r, offset + 16)),
            Vector256.Create(Vector128.LoadUnsafe(ref r, offset + 2), Vector128.LoadUnsafe(ref r, offset + 18)));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void StoreColumnsXor(Vector512<ulong> value, ref ulong x, ref ulong destination, nuint offset)
    {
        var low = value.GetLower();
        var high = value.GetUpper();
        StoreXor(low.GetLower(), ref x, ref destination, offset);
        StoreXor(low.GetUpper(), ref x, ref destination, offset + 16);
        StoreXor(high.GetLower(), ref x, ref destination, offset + 2);
        StoreXor(high.GetUpper(), ref x, ref destination, offset + 18);
    }

    // BlakeRoundNoMsg on two register sets, each two rows (or columns).
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Round512(
        ref Vector512<ulong> a,
        ref Vector512<ulong> b,
        ref Vector512<ulong> c,
        ref Vector512<ulong> d,
        ref Vector512<ulong> a2,
        ref Vector512<ulong> b2,
        ref Vector512<ulong> c2,
        ref Vector512<ulong> d2)
    {
        G512(ref a, ref b, ref c, ref d, ref a2, ref b2, ref c2, ref d2);
        b = Permute(b, 0b00_11_10_01, RotateOne);
        c = Permute(c, 0b01_00_11_10, RotateTwo);
        d = Permute(d, 0b10_01_00_11, RotateThree);
        b2 = Permute(b2, 0b00_11_10_01, RotateOne);
        c2 = Permute(c2, 0b01_00_11_10, RotateTwo);
        d2 = Permute(d2, 0b10_01_00_11, RotateThree);
        G512(ref a, ref b, ref c, ref d, ref a2, ref b2, ref c2, ref d2);
        b = Permute(b, 0b10_01_00_11, RotateThree);
        c = Permute(c, 0b01_00_11_10, RotateTwo);
        d = Permute(d, 0b00_11_10_01, RotateOne);
        b2 = Permute(b2, 0b10_01_00_11, RotateThree);
        c2 = Permute(c2, 0b01_00_11_10, RotateTwo);
        d2 = Permute(d2, 0b00_11_10_01, RotateOne);
    }

    // G on eight lanes of two register sets at once; see G for the scalar version.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void G512(
        ref Vector512<ulong> a,
        ref Vector512<ulong> b,
        ref Vector512<ulong> c,
        ref Vector512<ulong> d,
        ref Vector512<ulong> a2,
        ref Vector512<ulong> b2,
        ref Vector512<ulong> c2,
        ref Vector512<ulong> d2)
    {
        a = BlaMka(a, b);
        a2 = BlaMka(a2, b2);
        d = RotateRight(d ^ a, 32);
        d2 = RotateRight(d2 ^ a2, 32);
        c = BlaMka(c, d);
        c2 = BlaMka(c2, d2);
        b = RotateRight(b ^ c, 24);
        b2 = RotateRight(b2 ^ c2, 24);
        a = BlaMka(a, b);
        a2 = BlaMka(a2, b2);
        d = RotateRight(d ^ a, 16);
        d2 = RotateRight(d2 ^ a2, 16);
        c = BlaMka(c, d);
        c2 = BlaMka(c2, d2);
        b = RotateRight(b ^ c, 63);
        b2 = RotateRight(b2 ^ c2, 63);
    }

    // x + y + 2 * lo32(x) * lo32(y), per 64-bit lane: vpmuludq.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector512<ulong> BlaMka(Vector512<ulong> x, Vector512<ulong> y)
    {
        var xy = Avx512F.IsSupported
            ? Avx512F.Multiply(x.AsUInt32(), y.AsUInt32())
            : (x & Low32Mask) * (y & Low32Mask);
        return x + y + xy + xy;
    }

    // vprorq.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector512<ulong> RotateRight(Vector512<ulong> x, byte bits)
        => Avx512F.IsSupported
            ? Avx512F.RotateRight(x, bits)
            : Vector512.ShiftRightLogical(x, bits) | Vector512.ShiftLeft(x, 64 - bits);

    // vpermq with an immediate: the same lane rotation within each 256-bit half.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector512<ulong> Permute(Vector512<ulong> x, [ConstantExpected] byte control, Vector512<ulong> indices)
        => Avx512F.IsSupported ? Avx512F.Permute4x64(x, control) : Vector512.Shuffle(x, indices);
}
#endif
