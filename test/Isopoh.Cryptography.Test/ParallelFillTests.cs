// <copyright file="ParallelFillTests.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Test;

using System;
using System.Linq;
using System.Threading.Tasks;
using Isopoh.Cryptography.Argon2;
using TestLib;
using Xunit;

/// <summary>
/// Checks the hash when the lanes fill on more than one thread.
/// </summary>
public class ParallelFillTests
{
    /// <summary>
    /// Each published vector with four lanes gives its tag for every thread
    /// count, also when many hashes run at the same time and compete for the
    /// thread pool. After a full garbage collection with finalizers, the
    /// hashes still give the same tags.
    /// </summary>
    [Fact]
    public void ParallelHashesMatchThePublishedVectors()
    {
        Argon2TestVector[] vectors = PublishedVector.Argon2TestVectors.Where(v => v.Parallelism == 4).ToArray();
        Assert.NotEmpty(vectors);

        for (int round = 0; round < 2; ++round)
        {
            foreach (Argon2TestVector vector in vectors)
            {
                for (int threads = 1; threads <= 6; ++threads)
                {
                    Assert.Equal(vector.Tag, HashBytes(vector, threads));
                }
            }

            // More concurrent hashes than processors: each hash waits for its
            // lanes while the other hashes hold the thread pool.
            int concurrent = Math.Max(16, 4 * Environment.ProcessorCount);
            byte[][] tags = new byte[concurrent][];
            Parallel.For(0, concurrent, new ParallelOptions { MaxDegreeOfParallelism = concurrent }, i => tags[i] = HashBytes(vectors[i % vectors.Length], 4));
            for (int i = 0; i < concurrent; ++i)
            {
                Assert.Equal(vectors[i % vectors.Length].Tag, tags[i]);
            }

            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }

        static byte[] HashBytes(Argon2TestVector vector, int threads)
        {
            var config = new Argon2Config
            {
                Type = vector.Type,
                Version = vector.Version,
                TimeCost = vector.Iterations,
                MemoryCost = vector.MemoryKBytes,
                Lanes = vector.Parallelism,
                Threads = threads,
                HashLength = vector.TagLength,
                Password = vector.Password.ToArray(),
                Salt = vector.Salt.ToArray(),
                Secret = vector.Secret.ToArray(),
                AssociatedData = vector.AssociatedData.ToArray(),
            };
            using var argon2 = new Argon2(config);
            return argon2.Hash().ToArray();
        }
    }
}
