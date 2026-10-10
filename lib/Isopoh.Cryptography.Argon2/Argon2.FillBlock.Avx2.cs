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
/// AVX2 version of the permutation P, the same scheme as the reference
/// implementation's blamka-round-opt: the 16 words of a row (or column) are
/// held in four vectors A=(v0..v3), B=(v4..v7), C=(v8..v11), D=(v12..v15), so the
/// four column G functions are one vector G; the four diagonal ones are another
/// after rotating B, C and D by one, two and three lanes.
/// </summary>
public sealed partial class Argon2
{
    private static void PermuteAvx2(Span<ulong> block)
    {
        if (block.Length < QwordsInBlock)
        {
            throw new ArgumentException($"Expected a block of {QwordsInBlock} qwords, got {block.Length}.", nameof(block));
        }

        ref ulong r = ref MemoryMarshal.GetReference(block);

        // Rows: 16 consecutive words each.
        for (nuint i = 0; i < 8; ++i)
        {
            nuint row = 16 * i;
            var a = Vector256.LoadUnsafe(ref r, row);
            var b = Vector256.LoadUnsafe(ref r, row + 4);
            var c = Vector256.LoadUnsafe(ref r, row + 8);
            var d = Vector256.LoadUnsafe(ref r, row + 12);
            Round(ref a, ref b, ref c, ref d);
            a.StoreUnsafe(ref r, row);
            b.StoreUnsafe(ref r, row + 4);
            c.StoreUnsafe(ref r, row + 8);
            d.StoreUnsafe(ref r, row + 12);
        }

        // Columns: word pairs (2i, 2i+1) at strides of 16.
        for (nuint i = 0; i < 8; ++i)
        {
            nuint col = 2 * i;
            var a = Vector256.Create(Vector128.LoadUnsafe(ref r, col), Vector128.LoadUnsafe(ref r, col + 16));
            var b = Vector256.Create(Vector128.LoadUnsafe(ref r, col + 32), Vector128.LoadUnsafe(ref r, col + 48));
            var c = Vector256.Create(Vector128.LoadUnsafe(ref r, col + 64), Vector128.LoadUnsafe(ref r, col + 80));
            var d = Vector256.Create(Vector128.LoadUnsafe(ref r, col + 96), Vector128.LoadUnsafe(ref r, col + 112));
            Round(ref a, ref b, ref c, ref d);
            a.GetLower().StoreUnsafe(ref r, col);
            a.GetUpper().StoreUnsafe(ref r, col + 16);
            b.GetLower().StoreUnsafe(ref r, col + 32);
            b.GetUpper().StoreUnsafe(ref r, col + 48);
            c.GetLower().StoreUnsafe(ref r, col + 64);
            c.GetUpper().StoreUnsafe(ref r, col + 80);
            d.GetLower().StoreUnsafe(ref r, col + 96);
            d.GetUpper().StoreUnsafe(ref r, col + 112);
        }
    }

    // BlakeRoundNoMsg on four vectors.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Round(ref Vector256<ulong> a, ref Vector256<ulong> b, ref Vector256<ulong> c, ref Vector256<ulong> d)
    {
        // Columns: G(v0,v4,v8,v12) .. G(v3,v7,v11,v15).
        G4(ref a, ref b, ref c, ref d);

        // Diagonals: G(v0,v5,v10,v15) .. G(v3,v4,v9,v14).
        b = Avx2.Permute4x64(b, 0b00_11_10_01); // (v5, v6, v7, v4)
        c = Avx2.Permute4x64(c, 0b01_00_11_10); // (v10, v11, v8, v9)
        d = Avx2.Permute4x64(d, 0b10_01_00_11); // (v15, v12, v13, v14)
        G4(ref a, ref b, ref c, ref d);
        b = Avx2.Permute4x64(b, 0b10_01_00_11);
        c = Avx2.Permute4x64(c, 0b01_00_11_10);
        d = Avx2.Permute4x64(d, 0b00_11_10_01);
    }

    // G on four lanes at once; see G for the scalar version.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void G4(ref Vector256<ulong> a, ref Vector256<ulong> b, ref Vector256<ulong> c, ref Vector256<ulong> d)
    {
        a = BlaMka(a, b);
        d = Rotr32(d ^ a);
        c = BlaMka(c, d);
        b = Rotr24(b ^ c);
        a = BlaMka(a, b);
        d = Rotr16(d ^ a);
        c = BlaMka(c, d);
        b = Rotr63(b ^ c);
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
