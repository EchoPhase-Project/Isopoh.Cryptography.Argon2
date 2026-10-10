// <copyright file="Argon2.FillBlock.Avx2.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

#if NET8_0_OR_GREATER
namespace Isopoh.Cryptography.Argon2;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

/// <summary>
/// AVX2 version of the block fill, the same scheme as the reference
/// implementation's blamka-round-opt: the 16 words of a row (or column) are
/// held in four vectors A=(v0..v3), B=(v4..v7), C=(v8..v11), D=(v12..v15), so the
/// four column G functions are one vector G; the four diagonal ones are another
/// after rotating B, C and D by one, two and three lanes.
/// </summary>
public sealed partial class Argon2
{
    /// <summary>
    /// next = P(prev ^ ref) ^ (prev ^ ref) [^ next], in two passes over the
    /// block: the rows pass reads the inputs directly, the columns pass writes
    /// the output directly. The scalar path copies and XORs whole blocks
    /// around P instead, eight passes in all.
    /// </summary>
    /// <param name="prev">The previous block.</param>
    /// <param name="refBlock">The reference block.</param>
    /// <param name="next">The block to fill; with <paramref name="withXor"/>, XORed over.</param>
    /// <param name="buf">Working buffer of 2 * <see cref="QwordsInBlock"/>.</param>
    /// <param name="withXor">XOR the result over <paramref name="next"/> (passes after the first).</param>
    private static void FillBlockAvx2(ReadOnlySpan<ulong> prev, ReadOnlySpan<ulong> refBlock, Span<ulong> next, Span<ulong> buf, bool withXor)
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

        // Rows: 16 consecutive words each, loaded as prev ^ ref; two rows at a
        // time, two independent dependency chains for the CPU to overlap.
        for (nuint row = 0; row < QwordsInBlock; row += 32)
        {
            nuint s2 = row + 16;
            var a = Vector256.LoadUnsafe(ref f, row) ^ Vector256.LoadUnsafe(ref p, row);
            var b = Vector256.LoadUnsafe(ref f, row + 4) ^ Vector256.LoadUnsafe(ref p, row + 4);
            var c = Vector256.LoadUnsafe(ref f, row + 8) ^ Vector256.LoadUnsafe(ref p, row + 8);
            var d = Vector256.LoadUnsafe(ref f, row + 12) ^ Vector256.LoadUnsafe(ref p, row + 12);
            var a2 = Vector256.LoadUnsafe(ref f, s2) ^ Vector256.LoadUnsafe(ref p, s2);
            var b2 = Vector256.LoadUnsafe(ref f, s2 + 4) ^ Vector256.LoadUnsafe(ref p, s2 + 4);
            var c2 = Vector256.LoadUnsafe(ref f, s2 + 8) ^ Vector256.LoadUnsafe(ref p, s2 + 8);
            var d2 = Vector256.LoadUnsafe(ref f, s2 + 12) ^ Vector256.LoadUnsafe(ref p, s2 + 12);
            if (withXor)
            {
                (a ^ Vector256.LoadUnsafe(ref n, row)).StoreUnsafe(ref x, row);
                (b ^ Vector256.LoadUnsafe(ref n, row + 4)).StoreUnsafe(ref x, row + 4);
                (c ^ Vector256.LoadUnsafe(ref n, row + 8)).StoreUnsafe(ref x, row + 8);
                (d ^ Vector256.LoadUnsafe(ref n, row + 12)).StoreUnsafe(ref x, row + 12);
                (a2 ^ Vector256.LoadUnsafe(ref n, s2)).StoreUnsafe(ref x, s2);
                (b2 ^ Vector256.LoadUnsafe(ref n, s2 + 4)).StoreUnsafe(ref x, s2 + 4);
                (c2 ^ Vector256.LoadUnsafe(ref n, s2 + 8)).StoreUnsafe(ref x, s2 + 8);
                (d2 ^ Vector256.LoadUnsafe(ref n, s2 + 12)).StoreUnsafe(ref x, s2 + 12);
            }
            else
            {
                a.StoreUnsafe(ref x, row);
                b.StoreUnsafe(ref x, row + 4);
                c.StoreUnsafe(ref x, row + 8);
                d.StoreUnsafe(ref x, row + 12);
                a2.StoreUnsafe(ref x, s2);
                b2.StoreUnsafe(ref x, s2 + 4);
                c2.StoreUnsafe(ref x, s2 + 8);
                d2.StoreUnsafe(ref x, s2 + 12);
            }

            Round2(ref a, ref b, ref c, ref d, ref a2, ref b2, ref c2, ref d2);
            a.StoreUnsafe(ref r, row);
            b.StoreUnsafe(ref r, row + 4);
            c.StoreUnsafe(ref r, row + 8);
            d.StoreUnsafe(ref r, row + 12);
            a2.StoreUnsafe(ref r, s2);
            b2.StoreUnsafe(ref r, s2 + 4);
            c2.StoreUnsafe(ref r, s2 + 8);
            d2.StoreUnsafe(ref r, s2 + 12);
        }

        // Columns: word pairs (2i, 2i+1) at strides of 16, stored as result ^ x;
        // two columns at a time.
        for (nuint col = 0; col < 16; col += 4)
        {
            nuint c2o = col + 2;
            var a = Vector256.Create(Vector128.LoadUnsafe(ref r, col), Vector128.LoadUnsafe(ref r, col + 16));
            var b = Vector256.Create(Vector128.LoadUnsafe(ref r, col + 32), Vector128.LoadUnsafe(ref r, col + 48));
            var c = Vector256.Create(Vector128.LoadUnsafe(ref r, col + 64), Vector128.LoadUnsafe(ref r, col + 80));
            var d = Vector256.Create(Vector128.LoadUnsafe(ref r, col + 96), Vector128.LoadUnsafe(ref r, col + 112));
            var a2 = Vector256.Create(Vector128.LoadUnsafe(ref r, c2o), Vector128.LoadUnsafe(ref r, c2o + 16));
            var b2 = Vector256.Create(Vector128.LoadUnsafe(ref r, c2o + 32), Vector128.LoadUnsafe(ref r, c2o + 48));
            var c2 = Vector256.Create(Vector128.LoadUnsafe(ref r, c2o + 64), Vector128.LoadUnsafe(ref r, c2o + 80));
            var d2 = Vector256.Create(Vector128.LoadUnsafe(ref r, c2o + 96), Vector128.LoadUnsafe(ref r, c2o + 112));
            Round2(ref a, ref b, ref c, ref d, ref a2, ref b2, ref c2, ref d2);
            StoreXor(a.GetLower(), ref x, ref n, col);
            StoreXor(a.GetUpper(), ref x, ref n, col + 16);
            StoreXor(b.GetLower(), ref x, ref n, col + 32);
            StoreXor(b.GetUpper(), ref x, ref n, col + 48);
            StoreXor(c.GetLower(), ref x, ref n, col + 64);
            StoreXor(c.GetUpper(), ref x, ref n, col + 80);
            StoreXor(d.GetLower(), ref x, ref n, col + 96);
            StoreXor(d.GetUpper(), ref x, ref n, col + 112);
            StoreXor(a2.GetLower(), ref x, ref n, c2o);
            StoreXor(a2.GetUpper(), ref x, ref n, c2o + 16);
            StoreXor(b2.GetLower(), ref x, ref n, c2o + 32);
            StoreXor(b2.GetUpper(), ref x, ref n, c2o + 48);
            StoreXor(c2.GetLower(), ref x, ref n, c2o + 64);
            StoreXor(c2.GetUpper(), ref x, ref n, c2o + 80);
            StoreXor(d2.GetLower(), ref x, ref n, c2o + 96);
            StoreXor(d2.GetUpper(), ref x, ref n, c2o + 112);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void StoreXor(Vector128<ulong> value, ref ulong x, ref ulong destination, nuint offset)
        => (value ^ Vector128.LoadUnsafe(ref x, offset)).StoreUnsafe(ref destination, offset);

    // BlakeRoundNoMsg on two rows (or columns) of four vectors each.
    // Columns: G(v0,v4,v8,v12) .. G(v3,v7,v11,v15); diagonals after rotating
    // B, C and D by one, two and three lanes: G(v0,v5,v10,v15) .. G(v3,v4,v9,v14).
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Round2(
        ref Vector256<ulong> a,
        ref Vector256<ulong> b,
        ref Vector256<ulong> c,
        ref Vector256<ulong> d,
        ref Vector256<ulong> a2,
        ref Vector256<ulong> b2,
        ref Vector256<ulong> c2,
        ref Vector256<ulong> d2)
    {
        G4x2(ref a, ref b, ref c, ref d, ref a2, ref b2, ref c2, ref d2);
        b = Avx2.Permute4x64(b, 0b00_11_10_01);
        c = Avx2.Permute4x64(c, 0b01_00_11_10);
        d = Avx2.Permute4x64(d, 0b10_01_00_11);
        b2 = Avx2.Permute4x64(b2, 0b00_11_10_01);
        c2 = Avx2.Permute4x64(c2, 0b01_00_11_10);
        d2 = Avx2.Permute4x64(d2, 0b10_01_00_11);
        G4x2(ref a, ref b, ref c, ref d, ref a2, ref b2, ref c2, ref d2);
        b = Avx2.Permute4x64(b, 0b10_01_00_11);
        c = Avx2.Permute4x64(c, 0b01_00_11_10);
        d = Avx2.Permute4x64(d, 0b00_11_10_01);
        b2 = Avx2.Permute4x64(b2, 0b10_01_00_11);
        c2 = Avx2.Permute4x64(c2, 0b01_00_11_10);
        d2 = Avx2.Permute4x64(d2, 0b00_11_10_01);
    }

    // G on four lanes of two blocks of vectors at once; see G for the scalar version.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void G4x2(
        ref Vector256<ulong> a,
        ref Vector256<ulong> b,
        ref Vector256<ulong> c,
        ref Vector256<ulong> d,
        ref Vector256<ulong> a2,
        ref Vector256<ulong> b2,
        ref Vector256<ulong> c2,
        ref Vector256<ulong> d2)
    {
        a = BlaMka(a, b);
        a2 = BlaMka(a2, b2);
        d = Rotr32(d ^ a);
        d2 = Rotr32(d2 ^ a2);
        c = BlaMka(c, d);
        c2 = BlaMka(c2, d2);
        b = Rotr24(b ^ c);
        b2 = Rotr24(b2 ^ c2);
        a = BlaMka(a, b);
        a2 = BlaMka(a2, b2);
        d = Rotr16(d ^ a);
        d2 = Rotr16(d2 ^ a2);
        c = BlaMka(c, d);
        c2 = BlaMka(c2, d2);
        b = Rotr63(b ^ c);
        b2 = Rotr63(b2 ^ c2);
    }

    // x + y + 2 * lo32(x) * lo32(y), per 64-bit lane (FblaMka).
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> BlaMka(Vector256<ulong> x, Vector256<ulong> y)
    {
        Vector256<ulong> xy = Avx2.Multiply(x.AsUInt32(), y.AsUInt32());
        return Avx2.Add(Avx2.Add(x, y), Avx2.Add(xy, xy));
    }

    // Swap the 32-bit halves of each lane.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> Rotr32(Vector256<ulong> x)
        => Avx2.Shuffle(x.AsUInt32(), 0b10_11_00_01).AsUInt64();

    // Byte k of each result lane is byte (k + 3) mod 8 of the source lane.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> Rotr24(Vector256<ulong> x)
        => Avx2.Shuffle(
            x.AsByte(),
            Vector256.Create((byte)3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10)).AsUInt64();

    // Byte k of each result lane is byte (k + 2) mod 8 of the source lane.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> Rotr16(Vector256<ulong> x)
        => Avx2.Shuffle(
            x.AsByte(),
            Vector256.Create((byte)2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9)).AsUInt64();

    // Rotate right by 63 is rotate left by 1.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> Rotr63(Vector256<ulong> x)
        => Avx2.Or(Avx2.ShiftRightLogical(x, 63), Avx2.Add(x, x));
}
#endif
