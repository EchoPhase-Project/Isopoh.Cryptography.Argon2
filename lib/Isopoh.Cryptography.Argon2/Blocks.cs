// <copyright file="Blocks.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Break a byte array into blocks for Argon2 to use.
/// </summary>
public class Blocks
{
    /// <summary>
    /// The array of blocks broken into <see cref="BlockValues"/>
    /// which actually return the values in the original array.
    /// </summary>
    private readonly BlockValues[] blockValues;

    /// <summary>
    /// The arrays under <see cref="blockValues"/>, to tell whether a reset
    /// kept them (see <see cref="IsOver"/>).
    /// </summary>
    private readonly Memory<ulong>[] memories;

    /// <summary>
    /// Initializes a new instance of the <see cref="Blocks"/> class.
    /// </summary>
    /// <param name="memories">
    /// The arrays to use under the blocks.
    /// </param>
    public Blocks(IEnumerable<Memory<ulong>> memories)
    {
        this.memories = memories.ToArray();
        var bvs = new List<BlockValues>();
        var blockIndex = 0;
        foreach (Memory<ulong> memory in this.memories)
        {
            int maxBlockIndex = blockIndex + (memory.Length / Argon2.QwordsInBlock);
            for (int i = blockIndex; i < maxBlockIndex; ++i)
            {
                bvs.Add(new BlockValues(memory.Slice((i - blockIndex) * Argon2.QwordsInBlock, Argon2.QwordsInBlock)));
            }

            blockIndex = maxBlockIndex;
        }

        this.blockValues = bvs.ToArray();
    }

    /// <summary>
    /// Gets the total number of <see cref="BlockValues"/> in the <see cref="Blocks"/>.
    /// </summary>
    public int Length => this.blockValues.Length;

    /// <summary>
    /// Gets or sets the <see cref="BlockValues"/> element at the specified index.
    /// </summary>
    /// <param name="i">
    /// The <see cref="BlockValues"/> element to get or set.
    /// </param>
    /// <returns>
    /// The requested <see cref="BlockValues"/> element.
    /// </returns>
    public BlockValues this[int i] => this.blockValues[i];

    /// <summary>
    /// Whether these blocks lie over exactly <paramref name="other"/>, so a
    /// reset that kept its arrays can keep the blocks too instead of creating
    /// a <see cref="BlockValues"/> per block again.
    /// </summary>
    /// <param name="other">The arrays to compare with.</param>
    /// <returns>True if the arrays are the same ones, in the same order.</returns>
    internal bool IsOver(IReadOnlyList<Memory<ulong>> other)
    {
        if (other.Count != this.memories.Length)
        {
            return false;
        }

        for (int i = 0; i < this.memories.Length; ++i)
        {
            if (!this.memories[i].Equals(other[i]))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Gets the single array under all the blocks, when there is one (any
    /// memory under 2 GiB), so a hot loop can address blocks by offset
    /// instead of going through a <see cref="BlockValues"/> per block.
    /// </summary>
    /// <param name="memory">The array, block i at qword i * <see cref="Argon2.QwordsInBlock"/>.</param>
    /// <returns>True if the blocks lie over one array.</returns>
    internal bool TryGetContiguous(out Memory<ulong> memory)
    {
        if (this.memories.Length == 1)
        {
            memory = this.memories[0];
            return true;
        }

        memory = default;
        return false;
    }
}
