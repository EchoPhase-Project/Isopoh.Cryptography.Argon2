// <copyright file="LeakTests.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Test;

using System;
using Isopoh.Cryptography.Argon2;
using TestLib;
using Xunit;
using Xunit.Abstractions;

/// <summary>
/// Leak checks: managed heap growth, objects that are not collected, and
/// memory locks that are not released. The heap measurement covers the whole
/// process, so these run in a collection that runs alone (after the parallel
/// tests), not at the same time as other tests.
/// </summary>
[Collection(LeakTestCollection.Name)]
public class LeakTests
{
    private readonly ITestOutputHelper output;

    /// <summary>
    /// Initializes a new instance of the <see cref="LeakTests"/> class.
    /// </summary>
    /// <param name="output">Where to send the output.</param>
    public LeakTests(ITestOutputHelper output)
    {
        this.output = output;
    }

    /// <summary>
    /// Test <see cref="Argon2.Verify(string, string, Isopoh.Cryptography.SecureArray.SecureArrayCall)"/> for leaks.
    /// </summary>
    [Fact]
    public void TestLeakInVerify()
    {
        (bool passed, string text) = LeakInVerify.Test(this.output);
        Assert.True(passed, text);
    }

    /// <summary>
    /// Test <see cref="Argon2.Hash(Argon2Config)"/> for leaks.
    /// </summary>
    [Fact]
    public void TestLeakInHash()
    {
        (bool passed, string text) = LeakInHash.Test(this.output);
        Assert.True(passed, text);
    }

}

/// <summary>
/// The collection of <see cref="LeakTests"/>: xUnit runs it without other tests at the same time.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
#pragma warning disable SA1402 // the definition belongs with its tests.
public class LeakTestCollection
#pragma warning restore SA1402
{
    /// <summary>
    /// The name of the collection.
    /// </summary>
    public const string Name = "Leak tests";
}
