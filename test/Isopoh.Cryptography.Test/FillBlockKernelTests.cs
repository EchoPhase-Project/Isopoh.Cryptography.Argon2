// <copyright file="FillBlockKernelTests.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Test;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using Isopoh.Cryptography.Argon2;
using Xunit;
using Xunit.Abstractions;

/// <summary>
/// The vectorized block fills against a plain scalar transcription of the
/// RFC 9106 compression function G (the reference fill_block). The kernels
/// are private, so they are called through <see cref="UnsafeAccessorAttribute"/>
/// (the library is strong-named and the test assembly is not, so
/// InternalsVisibleTo is not an option).
/// </summary>
/// <remarks>
/// <see cref="Argon2"/>'s AVX-512 kernel runs on its portable Vector512 path
/// on machines without AVX-512, so this test checks that path everywhere and
/// the hardware path where it exists. Hash-level known-answer tests only
/// check the kernel the machine picks; this checks each kernel directly.
/// </remarks>
public class FillBlockKernelTests
{
    private const int QwordsInBlock = 128;

    private const int BlockCount = 2000;

    private readonly ITestOutputHelper output;

    /// <summary>
    /// Initializes a new instance of the <see cref="FillBlockKernelTests"/> class.
    /// </summary>
    /// <param name="output">Where to send the output.</param>
    public FillBlockKernelTests(ITestOutputHelper output)
    {
        this.output = output;
    }

    private delegate void Kernel(Argon2 type, ReadOnlySpan<ulong> prev, ReadOnlySpan<ulong> refBlock, Span<ulong> next, Span<ulong> buf, bool withXor);

    /// <summary>
    /// The AVX-512 kernel (hardware or portable) gives the scalar result for
    /// random blocks, with and without XOR over the next block.
    /// </summary>
    [Fact]
    public void Avx512KernelMatchesScalar()
    {
        this.output.WriteLine($"Avx512F.IsSupported={Avx512F.IsSupported}, Vector512.IsHardwareAccelerated={Vector512.IsHardwareAccelerated}");
        CheckKernel(FillBlockAvx512, seed: 512);
    }

    /// <summary>
    /// The AVX2 kernel gives the scalar result for random blocks, with and
    /// without XOR over the next block. It needs AVX2 hardware.
    /// </summary>
    [Fact]
    public void Avx2KernelMatchesScalar()
    {
        if (!Avx2.IsSupported)
        {
            this.output.WriteLine("AVX2 is not supported (or disabled): skipped.");
            return;
        }

        CheckKernel(FillBlockAvx2, seed: 256);
    }

    [UnsafeAccessor(UnsafeAccessorKind.StaticMethod, Name = "FillBlockAvx512")]
    private static extern void FillBlockAvx512(Argon2 type, ReadOnlySpan<ulong> prev, ReadOnlySpan<ulong> refBlock, Span<ulong> next, Span<ulong> buf, bool withXor);

    [UnsafeAccessor(UnsafeAccessorKind.StaticMethod, Name = "FillBlockAvx2")]
    private static extern void FillBlockAvx2(Argon2 type, ReadOnlySpan<ulong> prev, ReadOnlySpan<ulong> refBlock, Span<ulong> next, Span<ulong> buf, bool withXor);

    private static void CheckKernel(Kernel kernel, int seed)
    {
        var random = new Random(seed);
        var prev = new ulong[QwordsInBlock];
        var refBlock = new ulong[QwordsInBlock];
        var next = new ulong[QwordsInBlock];
        var buf = new ulong[2 * QwordsInBlock];
        int failures = 0;
        int firstFailure = -1;
        for (int i = 0; i < BlockCount; ++i)
        {
            bool withXor = (i & 1) == 1;
            FillRandom(random, prev, edges: i % 7 == 0);
            FillRandom(random, refBlock, edges: i % 11 == 0);
            FillRandom(random, next, edges: false);

            // Garbage in the working buffer must not matter.
            FillRandom(random, buf, edges: false);
            ulong[] expected = ScalarFillBlock(prev, refBlock, next, withXor);
            ulong[] prevCopy = (ulong[])prev.Clone();
            ulong[] refCopy = (ulong[])refBlock.Clone();
            kernel(null, prev, refBlock, next, buf, withXor);
            if (!next.AsSpan().SequenceEqual(expected) || !prev.AsSpan().SequenceEqual(prevCopy) || !refBlock.AsSpan().SequenceEqual(refCopy))
            {
                ++failures;
                if (firstFailure < 0)
                {
                    firstFailure = i;
                }
            }
        }

        Assert.True(failures == 0, $"{failures} of {BlockCount} blocks differ from the scalar fill (first: block {firstFailure}).");
    }

    private static void FillRandom(Random random, ulong[] block, bool edges)
    {
        for (int i = 0; i < block.Length; ++i)
        {
            block[i] = (ulong)random.NextInt64() ^ ((ulong)random.Next(2) << 63);
        }

        if (edges)
        {
            // Words that stress the 32x32 multiply and the carries.
            block[random.Next(block.Length)] = ulong.MaxValue;
            block[random.Next(block.Length)] = 0;
            block[random.Next(block.Length)] = 0xFFFF_FFFFUL;
            block[random.Next(block.Length)] = 0xFFFF_FFFF_0000_0000UL;
        }
    }

    /// <summary>
    /// RFC 9106 section 3.5: R = X ^ Y, Q = P applied to the rows of R, Z = P
    /// applied to the columns of Q, result Z ^ R (and with XOR, ^ the old next).
    /// </summary>
    private static ulong[] ScalarFillBlock(ulong[] prev, ulong[] refBlock, ulong[] next, bool withXor)
    {
        var r = new ulong[QwordsInBlock];
        for (int i = 0; i < QwordsInBlock; ++i)
        {
            r[i] = prev[i] ^ refBlock[i];
        }

        var z = (ulong[])r.Clone();
        var index = new int[16];

        // Rows: 16 consecutive words each.
        for (int row = 0; row < 8; ++row)
        {
            for (int j = 0; j < 16; ++j)
            {
                index[j] = (16 * row) + j;
            }

            Permute(z, index);
        }

        // Columns: two adjacent words from each of the 8 rows.
        for (int column = 0; column < 8; ++column)
        {
            for (int j = 0; j < 8; ++j)
            {
                index[2 * j] = (2 * column) + (16 * j);
                index[(2 * j) + 1] = (2 * column) + (16 * j) + 1;
            }

            Permute(z, index);
        }

        var result = new ulong[QwordsInBlock];
        for (int i = 0; i < QwordsInBlock; ++i)
        {
            result[i] = z[i] ^ r[i] ^ (withXor ? next[i] : 0);
        }

        return result;
    }

    private static void Permute(ulong[] block, int[] index)
    {
        var v = new ulong[16];
        for (int i = 0; i < 16; ++i)
        {
            v[i] = block[index[i]];
        }

        G(v, 0, 4, 8, 12);
        G(v, 1, 5, 9, 13);
        G(v, 2, 6, 10, 14);
        G(v, 3, 7, 11, 15);
        G(v, 0, 5, 10, 15);
        G(v, 1, 6, 11, 12);
        G(v, 2, 7, 8, 13);
        G(v, 3, 4, 9, 14);
        for (int i = 0; i < 16; ++i)
        {
            block[index[i]] = v[i];
        }
    }

    private static void G(ulong[] v, int a, int b, int c, int d)
    {
        v[a] = BlaMka(v[a], v[b]);
        v[d] = ulong.RotateRight(v[d] ^ v[a], 32);
        v[c] = BlaMka(v[c], v[d]);
        v[b] = ulong.RotateRight(v[b] ^ v[c], 24);
        v[a] = BlaMka(v[a], v[b]);
        v[d] = ulong.RotateRight(v[d] ^ v[a], 16);
        v[c] = BlaMka(v[c], v[d]);
        v[b] = ulong.RotateRight(v[b] ^ v[c], 63);
    }

    private static ulong BlaMka(ulong x, ulong y) => x + y + (2 * (x & 0xFFFF_FFFFUL) * (y & 0xFFFF_FFFFUL));
}
