// <copyright file="BlockOps.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2;

using System;
#if NET8_0_OR_GREATER
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
#endif

/// <summary>
/// Whole-block operations shared by the block value types.
/// </summary>
internal static class BlockOps
{
    /// <summary>
    /// XOR <paramref name="source"/> into <paramref name="destination"/>, one block (<see cref="Argon2.QwordsInBlock"/> qwords).
    /// </summary>
    /// <param name="destination">The block XORed into.</param>
    /// <param name="source">The block XORed in.</param>
    /// <exception cref="ArgumentException">If either span is shorter than a block.</exception>
    public static void Xor(Span<ulong> destination, ReadOnlySpan<ulong> source)
    {
        if (destination.Length < Argon2.QwordsInBlock || source.Length < Argon2.QwordsInBlock)
        {
            throw new ArgumentException($"Expected blocks of {Argon2.QwordsInBlock} qwords, got {destination.Length} and {source.Length}.");
        }

#if NET8_0_OR_GREATER
        // A block is 128 qwords: a whole number of vectors at every width, no tail.
        ref ulong d = ref MemoryMarshal.GetReference(destination);
        ref ulong s = ref MemoryMarshal.GetReference(source);
        if (Vector256.IsHardwareAccelerated)
        {
            for (nuint i = 0; i < Argon2.QwordsInBlock; i += 4)
            {
                (Vector256.LoadUnsafe(ref d, i) ^ Vector256.LoadUnsafe(ref s, i)).StoreUnsafe(ref d, i);
            }

            return;
        }

        if (Vector128.IsHardwareAccelerated)
        {
            for (nuint i = 0; i < Argon2.QwordsInBlock; i += 2)
            {
                (Vector128.LoadUnsafe(ref d, i) ^ Vector128.LoadUnsafe(ref s, i)).StoreUnsafe(ref d, i);
            }

            return;
        }
#endif

        for (var i = 0; i < Argon2.QwordsInBlock; ++i)
        {
            destination[i] ^= source[i];
        }
    }
}
