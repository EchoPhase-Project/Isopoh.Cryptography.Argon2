// <copyright file="Blake2BTests.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Test;

using System;
using System.Linq;
using Isopoh.Cryptography.Blake2b;
using Isopoh.Cryptography.SecureArray;
using Xunit;

/// <summary>
/// BLAKE2b against reference values (Python's hashlib.blake2b, which wraps the
/// reference implementation), through each entry point and option.
/// </summary>
public class Blake2BTests
{
    private const string EmptyHash = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce";
    private const string AbcHash = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";
    private const string Keyed200Hash = "3095a349d245708c7cf550118703d7302c27b60af5d4e67fc978f8a4e60953c7a04f92fcf41aee64321ccb707a895851552b1e37b00bc5e6b72fa5bcef9e3fff";

    private static readonly byte[] Data = Enumerable.Range(0, 200).Select(i => (byte)i).ToArray();

    private static readonly byte[] Key64 = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();

    private static SecureArrayCall Call => SecureArray.DefaultCall;

    /// <summary>
    /// The unkeyed digest of the empty input and of "abc".
    /// </summary>
    [Fact]
    public void ComputeHashMatchesReference()
    {
        Assert.Equal(EmptyHash, Hex(Blake2B.ComputeHash(Array.Empty<byte>(), Call)));
        Assert.Equal(AbcHash, Hex(Blake2B.ComputeHash("abc"u8.ToArray(), Call)));
    }

    /// <summary>
    /// A 64-byte key, as in the reference keyed test vectors.
    /// </summary>
    [Fact]
    public void KeyedHashMatchesReference()
    {
        Assert.Equal(
            "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
            Hex(Blake2B.ComputeHash(Array.Empty<byte>(), new Blake2BConfig { Key = Key64 }, Call)));
        Assert.Equal(Keyed200Hash, Hex(Blake2B.ComputeHash(Data, new Blake2BConfig { Key = Key64 }, Call)));
    }

    /// <summary>
    /// Salt, personalization and a shorter output change the digest as in the reference.
    /// </summary>
    [Fact]
    public void SaltPersonalizationAndOutputSize()
    {
        var config = new Blake2BConfig
        {
            Salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray(),
            Personalization = "EchoPhaseTest!!!"u8.ToArray(),
            OutputSizeInBits = 256,
        };
        Assert.Equal(32, config.OutputSizeInBytes);
        Assert.Equal(
            "4988e884802222896ac705da04e9da4999f8f04671d96538eb22d241b23e26f2",
            Hex(Blake2B.ComputeHash(Data, config, Call)));

        Assert.Equal("5f", Hex(Blake2B.ComputeHash(Data, new Blake2BConfig { OutputSizeInBytes = 1 }, Call)));
        Assert.Equal(
            "09c648717a89a7e0caba9558d20d0bde4d4077e4",
            Hex(Blake2B.ComputeHash(Data, new Blake2BConfig { OutputSizeInBytes = 20, Key = new byte[] { 1, 2, 3, 4, 5 } }, Call)));
    }

    /// <summary>
    /// Hashing a slice of an array, and the span overload with a caller's buffer.
    /// </summary>
    [Fact]
    public void SliceAndSpanOverloads()
    {
        const string slice = "6a17501b3590b68ea73bd4addb4ecddbb105b625d543fdbe16cfbb6606e4489791fd16c2bc50272504fefe9d724a5abb67df2066baee982fefb8304becc9b8d7";
        Assert.Equal(slice, Hex(Blake2B.ComputeHash(Data, 10, 100, Call)));
        Assert.Equal(slice, Hex(Blake2B.ComputeHash(Data, 10, 100, new Blake2BConfig(), Call)));

        var buffer = new byte[Blake2B.BufferMinimumTotalSize];
        Assert.Equal(Keyed200Hash, Hex(Blake2B.ComputeHash(Data, new Blake2BConfig { Key = Key64 }, buffer)));
        var noKeyBuffer = new byte[Blake2B.NoKeyBufferMinimumTotalSize];
        Assert.Equal(AbcHash, Hex(Blake2B.ComputeHash("abc"u8, null, noKeyBuffer)));
    }

    /// <summary>
    /// Incremental updates in uneven pieces give the one-shot digest; the hasher can be reused after Init.
    /// </summary>
    [Fact]
    public void IncrementalUpdatesAndReuse()
    {
        using Hasher hasher = Blake2B.Create(new Blake2BConfig { Key = Key64 }, Call);
        hasher.Update(Data, 0, 1);
        hasher.Update(Data.AsSpan(1, 127));
        hasher.Update(Data, 128, 72);
        Assert.Equal(Keyed200Hash, Hex(hasher.Finish()));

        hasher.Init();
        hasher.Update(Data);
        Assert.Equal(Keyed200Hash, Hex(hasher.Finish()));

        using Hasher unkeyed = Blake2B.Create(Call);
        unkeyed.Update("abc"u8.ToArray());
        Assert.Equal(AbcHash, Hex(unkeyed.Finish()));

        using Hasher fromBuffer = Blake2B.Create(new byte[Blake2B.BufferMinimumTotalSize]);
        fromBuffer.Update("abc"u8);
        Assert.Equal(AbcHash, Hex(fromBuffer.Finish()));
    }

    /// <summary>
    /// Finish into a caller's span: bigger (rest cleared), smaller (truncated), and into the config's 64-byte buffer.
    /// </summary>
    [Fact]
    public void FinishIntoSpans()
    {
        using Hasher hasher = Blake2B.Create(new Blake2BConfig(), Call);
        hasher.Update("abc"u8);
        var big = Enumerable.Repeat((byte)0xAA, 80).ToArray();
        hasher.Finish(big);
        Assert.Equal(AbcHash, Hex(big.AsSpan(0, 64).ToArray()));
        Assert.All(big.Skip(64), b => Assert.Equal(0, b));

        hasher.Init();
        hasher.Update("abc"u8);
        var small = new byte[10];
        hasher.Finish(small);
        Assert.Equal(AbcHash.Substring(0, 20), Hex(small));

        var result = new byte[64];
        using Hasher withResultBuffer = Blake2B.Create(new Blake2BConfig { Result64ByteBuffer = result, OutputSizeInBytes = 32 }, Call);
        withResultBuffer.Update("abc"u8);
        Memory<byte> hash = withResultBuffer.Finish();
        Assert.Equal(32, hash.Length);
        Assert.True(hash.Span.Overlaps(result));
        withResultBuffer.Init();
        withResultBuffer.Update("abc"u8);
        var into = new byte[64];
        withResultBuffer.Finish(into);
        Assert.Equal(result, into);
    }

    /// <summary>
    /// The System.Security.Cryptography.HashAlgorithm view of a hasher.
    /// </summary>
    [Fact]
    public void AsHashAlgorithm()
    {
        using Hasher hasher = Blake2B.Create(new Blake2BConfig(), Call);
        using System.Security.Cryptography.HashAlgorithm algorithm = hasher.AsHashAlgorithm();
        Assert.Equal(AbcHash, Hex(algorithm.ComputeHash("abc"u8.ToArray())));
        algorithm.Initialize();
        Assert.Equal(EmptyHash, Hex(algorithm.ComputeHash(Array.Empty<byte>())));
    }

    /// <summary>
    /// The key and IV a hasher exposes, and that a disposed hasher refuses to work.
    /// </summary>
    [Fact]
    public void KeyIvAndDisposal()
    {
        var hasher = new Blake2BHasher(new Blake2BConfig { Key = new byte[] { 7, 8, 9 } }, Call);
        Assert.Equal(128, hasher.Key.Length);
        Assert.Equal(new byte[] { 7, 8, 9 }, hasher.Key.Slice(0, 3).ToArray());
        Assert.Equal(8, hasher.Iv.Length);
        hasher.Dispose();
        hasher.Dispose();
        Assert.Throws<ObjectDisposedException>(() => hasher.Init());
        Assert.Throws<ObjectDisposedException>(() => hasher.Update(new byte[1]));
        Assert.Throws<ObjectDisposedException>(() => hasher.Finish());
        Assert.Throws<ObjectDisposedException>(() => hasher.Finish(new byte[64]));
        Assert.Throws<ObjectDisposedException>(() => hasher.Key.Length);
        Assert.Throws<ObjectDisposedException>(() => hasher.Iv.Length);
    }

    /// <summary>
    /// Configuration values outside what BLAKE2b allows.
    /// </summary>
    [Fact]
    public void InvalidConfiguration()
    {
        var config = new Blake2BConfig();
        Assert.Throws<ArgumentException>(() => config.Salt = new byte[15]);
        Assert.Throws<ArgumentException>(() => config.Personalization = new byte[17]);
        Assert.Throws<ArgumentException>(() => config.Key = new byte[129]);
        Assert.Throws<ArgumentOutOfRangeException>(() => config.OutputSizeInBytes = 65);
        Assert.Throws<ArgumentException>(() => config.OutputSizeInBits = 12);
        Assert.Throws<ArgumentOutOfRangeException>(() => config.Result64ByteBuffer = new byte[32]);
        config.Salt = null;
        config.Personalization = null;
        config.Key = null;
        config.Result64ByteBuffer = null;
        Assert.Null(config.Salt);
        Assert.Equal(LockMemoryPolicy.BestEffort, config.LockMemoryPolicy);

        // Accepted by the config (up to 128 bytes) but not by BLAKE2b itself (64).
        Assert.ThrowsAny<ArgumentException>(() => Blake2B.Create(new Blake2BConfig { Key = new byte[100] }, Call));
        Assert.ThrowsAny<ArgumentException>(() => Blake2B.Create(new Blake2BConfig { OutputSizeInBytes = 0 }, Call));

        using Hasher hasher = Blake2B.Create(Call);
        Assert.Throws<ArgumentNullException>(() => hasher.Update(null!));
        Assert.Throws<ArgumentNullException>(() => hasher.Update(null!, 0, 0));
    }

    /// <summary>
    /// A caller's buffer too small for the hasher's state.
    /// </summary>
    [Fact]
    public void BufferTooSmall()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Blake2B.Create(new byte[Blake2B.NoKeyBufferMinimumTotalSize - 1]));
        Assert.Throws<ArgumentOutOfRangeException>(() => Blake2B.Create(new Blake2BConfig { Key = Key64 }, new byte[Blake2B.NoKeyBufferMinimumTotalSize]));
    }

    /// <summary>
    /// The tree parameters for interleaved hashing.
    /// </summary>
    [Fact]
    public void InterleavedTreeConfig()
    {
        var tree = Blake2BTreeConfig.CreateInterleaved(4);
        Assert.Equal(4, tree.FanOut);
        Assert.Equal(2, tree.MaxHeight);
        Assert.Equal(64, tree.IntermediateHashSize);
        tree.LeafSize = 4096;
        Assert.Equal(4096, tree.LeafSize);
    }

    private static string Hex(Memory<byte> bytes) => Hex(bytes.ToArray());

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
}
