// <copyright file="Argon2ApiTests.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Test;

using System;
using System.Linq;
using System.Text;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;
using Xunit;

/// <summary>
/// The public Argon2 API around the hash itself: the encoded string format both
/// ways, every Hash and Verify overload, configuration checks and the reusable
/// <see cref="Argon2Memory"/>. Small costs keep it fast; correctness of the
/// digest is the test vectors' job.
/// </summary>
public class Argon2ApiTests
{
    private static readonly byte[] Salt = Encoding.UTF8.GetBytes("somesaltsomesalt");

    /// <summary>
    /// A full encoded hash decodes into the configuration that produced it, for each type and version.
    /// </summary>
    /// <param name="type">Argon2 variant.</param>
    /// <param name="version">Argon2 version.</param>
    [Theory]
    [InlineData(Argon2Type.DataIndependentAddressing, Argon2Version.Nineteen)]
    [InlineData(Argon2Type.DataDependentAddressing, Argon2Version.Nineteen)]
    [InlineData(Argon2Type.HybridAddressing, Argon2Version.Sixteen)]
    public void EncodeDecodeRoundTrip(Argon2Type type, Argon2Version version)
    {
        var config = Config(type, version);
        config.AssociatedData = new byte[] { 1, 2, 3, 4, 5 };
        string encoded = Argon2.Hash(config);

        var decoded = new Argon2Config();
        Assert.True(decoded.DecodeString(encoded, out var hash));
        using (hash)
        {
            Assert.Equal(type, decoded.Type);
            Assert.Equal(version, decoded.Version);
            Assert.Equal(config.MemoryCost, decoded.MemoryCost);
            Assert.Equal(config.TimeCost, decoded.TimeCost);
            Assert.Equal(config.Lanes, decoded.Lanes);
            Assert.Equal(config.AssociatedData, decoded.AssociatedData);
            Assert.Equal(Salt, decoded.Salt);
            Assert.Equal(20, hash!.Buffer.Length);
        }

        decoded.Password = Encoding.UTF8.GetBytes("password");
        Assert.True(Argon2.Verify(encoded, decoded));
    }

    /// <summary>
    /// Encoded strings without hash, salt or version decode to as much as they hold.
    /// </summary>
    [Fact]
    public void DecodePartialStrings()
    {
        var config = new Argon2Config();
        Assert.True(config.DecodeString("$argon2id$v=19$m=64,t=2,p=3", out var noHash));
        Assert.Null(noHash);
        Assert.Equal(64, config.MemoryCost);
        Assert.Equal(3, config.Threads);

        string salt = ((Span<byte>)Salt).ToB64String();
        Assert.True(config.DecodeString($"$argon2d$m=32,t=1,p=1$" + salt, out var saltOnly));
        Assert.Null(saltOnly);
        Assert.Equal(Argon2Version.Sixteen, config.Version);
        Assert.Equal(Salt, config.Salt);

        Assert.True(config.DecodeString("$argon2i$v=19$m=32,t=1,p=1,data=AQID", out _));
        Assert.Equal(new byte[] { 1, 2, 3 }, config.AssociatedData);
    }

    /// <summary>
    /// Malformed strings are refused, not half-decoded.
    /// </summary>
    /// <param name="encoded">The string to decode.</param>
    [Theory]
    [InlineData("$argon2x$v=19$m=32,t=1,p=1")]
    [InlineData("$argon2id$v=x$m=32,t=1,p=1")]
    [InlineData("$argon2id$v=19$q=32,t=1,p=1")]
    [InlineData("$argon2id$v=19$m=32,x=1,p=1")]
    [InlineData("$argon2id$v=19$m=32,t=1,x=1")]
    [InlineData("$argon2id$v=19$m=32,t=1,p=1,data=A")]
    [InlineData("$argon2id$v=19$m=32,t=1,p=1#")]
    [InlineData("$argon2id$v=19$m=32,t=1,p=1$c29tZXNhbHRzb21lc2FsdA#")]
    [InlineData("$argon2id$v=19$m=32,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$A")]
    [InlineData("$argon2id$v=19$m=32,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$AAAA#")]
    [InlineData("$argon2id$v=19$m=32,t=1,p=1$A$AAAA")]
    [InlineData("$argon2id$v=19$m=99999999999,t=1,p=1")]
    public void DecodeRejectsMalformed(string encoded)
    {
        Assert.False(new Argon2Config().DecodeString(encoded, out var hash));
        Assert.Null(hash);
    }

    /// <summary>
    /// The regex decoder used by <see cref="Argon2Memory"/>: buffer lengths, key id, data and errors.
    /// </summary>
    [Fact]
    public void DecodeIntoMemory()
    {
        byte[] keyId = { 9, 8, 7, 6 };
        byte[] data = { 1, 2, 3, 4, 5, 6, 7 };
        byte[] hash = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        string encoded = EncodeExtension.EncodeString(
            Argon2Type.HybridAddressing, Argon2Version.Nineteen, 32, 2, 1, keyId, data, Salt, hash);
        Assert.Contains("keyid=", encoded);

        var lengths = encoded.Argon2RequiredBufferLengths();
        Assert.Equal((4, 7, Salt.Length, 16), lengths);

        using var memory = new Argon2Memory(Config(Argon2Type.HybridAddressing, Argon2Version.Nineteen), Argon2MemoryPolicy.NoShrink, null);
        memory.DecodeString(encoded);
        Assert.Equal(keyId, memory.KeyIdentifier.ToArray());
        Assert.Equal(data, memory.AssociatedData.ToArray());
        Assert.Equal(hash, memory.Hash.ToArray());
        Assert.Equal(2, memory.TimeCost);

        string salt = ((Span<byte>)Salt).ToB64String();
        string digest = ((Span<byte>)hash).ToB64String();
        memory.DecodeString($"$argon2i$v=16$m=32,t=1,p=1${salt}${digest}");
        Assert.Equal(Argon2Version.Sixteen, memory.Version);
        Assert.Equal(Argon2Type.DataIndependentAddressing, memory.Type);
        memory.DecodeString($"$argon2d$m=32,t=1,p=1${salt}${digest}");
        Assert.Equal(Argon2Type.DataDependentAddressing, memory.Type);

        // A memory holds a hash to verify: a string without salt or digest is refused.
        Assert.Throws<ArgumentException>(() => memory.DecodeString("$argon2i$v=19$m=32,t=1,p=1"));

        Assert.Throws<ArgumentException>(() => "nonsense".Argon2RequiredBufferLengths());
        Assert.Throws<ArgumentNullException>(() => ((string)null!).Argon2RequiredBufferLengths());
        Assert.Throws<ArgumentException>(() => memory.DecodeString("nonsense"));
        Assert.Throws<ArgumentNullException>(() => memory.DecodeString(null!));
        Assert.Throws<ArgumentNullException>(() => new Argon2Config().DecodeString(null!, out _));
        Assert.Throws<ArgumentNullException>(() => ((Argon2Config)null!).DecodeString("$argon2id$m=1,t=1,p=1", out _));
    }

    /// <summary>
    /// Every Hash and Verify overload accepts the right password and refuses a wrong one.
    /// </summary>
    [Fact]
    public void HashAndVerifyOverloads()
    {
        const string password = "password";
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        const string secret = "secret";
        byte[] secretBytes = Encoding.UTF8.GetBytes(secret);

        string plain = Argon2.Hash(password, timeCost: 1, memoryCost: 32, parallelism: 2, hashLength: 16);
        Assert.True(Argon2.Verify(plain, password));
        Assert.True(Argon2.Verify(plain, password, 1));
        Assert.True(Argon2.Verify(plain, passwordBytes));
        Assert.True(Argon2.Verify(plain, passwordBytes, 2));
        Assert.False(Argon2.Verify(plain, "wrong"));
        Assert.False(Argon2.Verify(plain, Encoding.UTF8.GetBytes("wrong"), 1));

        string withSecret = Argon2.Hash(password, secret, timeCost: 1, memoryCost: 32, type: Argon2Type.DataDependentAddressing);
        Assert.True(Argon2.Verify(withSecret, password, secret));
        Assert.True(Argon2.Verify(withSecret, password, secret, 1));
        Assert.True(Argon2.Verify(withSecret, passwordBytes, secretBytes));
        Assert.True(Argon2.Verify(withSecret, passwordBytes, secretBytes, 1));
        Assert.False(Argon2.Verify(withSecret, password, "other"));
        Assert.False(Argon2.Verify(withSecret, password));

        string fromBytes = Argon2.Hash(passwordBytes, secretBytes, timeCost: 1, memoryCost: 32, type: Argon2Type.DataIndependentAddressing);
        Assert.True(Argon2.Verify(fromBytes, password, secret));

        Assert.False(Argon2.Verify("not an argon2 hash", password));
        Assert.False(Argon2.Verify("$argon2id$v=19$m=32,t=1,p=1", password));
    }

    /// <summary>
    /// Hashing and verifying through a reused <see cref="Argon2Memory"/>, with each password reset policy.
    /// </summary>
    [Fact]
    public void ReusedMemory()
    {
        var config = Config(Argon2Type.HybridAddressing, Argon2Version.Nineteen);
        using var memory = new Argon2Memory(config, Argon2MemoryPolicy.Shrink, LockMemoryPolicy.BestEffort);
        string encoded = Argon2.Hash(memory);
        Assert.Equal(Argon2.Hash(config), encoded);

        Assert.True(Argon2.Verify(encoded, memory));

        memory.Reset(encoded, new Argon2Password(Encoding.UTF8.GetBytes("password")));
        Assert.Equal("password", Encoding.UTF8.GetString(memory.Password));
        memory.Reset(encoded, Argon2Password.Keep);
        Assert.Equal("password", Encoding.UTF8.GetString(memory.Password));
        memory.Reset(encoded, (Argon2Password)Argon2ExistingPasswordResetPolicy.Clear);
        Assert.Equal(0, memory.Password.Length);
        Assert.False(Argon2.Verify(encoded, memory));

        memory.StartUse();
        Assert.True(memory.InUse);
        Assert.Throws<InvalidOperationException>(() => memory.Reset(config));
        memory.EndUse();

        // Growing then shrinking the memory cost, with each memory policy.
        var bigger = Config(Argon2Type.DataDependentAddressing, Argon2Version.Sixteen);
        bigger.MemoryCost = 256;
        bigger.Lanes = 4;
        bigger.Threads = 2;
        memory.Reset(bigger);
        Assert.Equal(256, memory.BlockCount);
        memory.ShrinkMemoryPolicy = Argon2MemoryPolicy.NoShrink;
        memory.Reset(config);
        memory.ShrinkMemoryPolicy = Argon2MemoryPolicy.Shrink;
        memory.Reset(config);
        using var hasher = new Argon2(memory);
        Assert.Equal(memory.BlockCount, hasher.MemoryBlockCount);
        Assert.Equal(memory.LaneBlockCount, hasher.LaneBlockCount);
        Assert.Equal(memory.SegmentBlockCount, hasher.SegmentBlockCount);
        Assert.Equal(hasher.MemoryBlockCount, hasher.Memory.Length);
        Assert.Equal(20, hasher.Hash().Length);

        var (segment, lane, total) = Argon2Memory.RequiredBlockCounts(bigger);
        Assert.Equal(256UL, total);
        Assert.Equal(64, lane);
        Assert.Equal(16, segment);
    }

    /// <summary>
    /// ClearPassword and ClearSecret wipe the copies Argon2 hashed from.
    /// </summary>
    [Fact]
    public void ClearPasswordAndSecret()
    {
        var config = Config(Argon2Type.HybridAddressing, Argon2Version.Nineteen);
        config.Secret = Encoding.UTF8.GetBytes("secret");
        config.ClearPassword = true;
        config.ClearSecret = true;
        using var memory = new Argon2Memory(config, Argon2MemoryPolicy.NoShrink, null);
        Assert.Equal("password", Encoding.UTF8.GetString(memory.Password));
        using (var hasher = new Argon2(memory))
        {
            hasher.Hash();
        }

        Assert.All(memory.Password.ToArray(), b => Assert.Equal(0, b));
        Assert.All(memory.Secret.ToArray(), b => Assert.Equal(0, b));
    }

    /// <summary>
    /// Configuration values Argon2 does not allow, and Clone.
    /// </summary>
    [Fact]
    public void ConfigurationChecksAndClone()
    {
        var config = new Argon2Config();
        Assert.Throws<ArgumentException>(() => config.HashLength = 3);
        Assert.Throws<ArgumentException>(() => config.Salt = new byte[7]);
        Assert.Throws<ArgumentException>(() => config.TimeCost = 0);
        Assert.Throws<ArgumentException>(() => config.MemoryCost = 0);
        Assert.Throws<ArgumentException>(() => config.Lanes = 0);
        Assert.Throws<ArgumentException>(() => config.Lanes = int.MaxValue);
        Assert.Throws<ArgumentException>(() => config.Threads = 0);

        // A salt is made up when none is given.
        Assert.Equal(16, new Argon2Config().Salt!.Length);

        var original = Config(Argon2Type.DataDependentAddressing, Argon2Version.Sixteen);
        original.Secret = new byte[] { 1 };
        original.AssociatedData = new byte[] { 2 };
        original.KeyIdentifier = new byte[] { 3 };
        var clone = (Argon2Config)original.Clone();
        Assert.Equal(original.Password, clone.Password);
        Assert.NotSame(original.Password, clone.Password);
        Assert.Equal(original.KeyIdentifier, clone.KeyIdentifier);
        Assert.Equal(Argon2.Hash(original), Argon2.Hash(clone));
        Assert.True(clone.WorkingBufferLength > 0);
    }

    /// <summary>
    /// The password wrapper's conversions.
    /// </summary>
    [Fact]
    public void PasswordConversions()
    {
        Span<byte> bytes = new byte[] { 1, 2, 3 };
        Argon2Password password = (Argon2Password)bytes;
        Span<byte> back = password;
        Assert.Equal(3, back.Length);
        Argon2ExistingPasswordResetPolicy policy = Argon2Password.Keep;
        Assert.Equal(Argon2ExistingPasswordResetPolicy.Keep, policy);
        Assert.Equal(Argon2ExistingPasswordResetPolicy.Clear, new Argon2Password(Argon2ExistingPasswordResetPolicy.Clear).Policy);
    }

    /// <summary>
    /// Constant-time comparison of different lengths and contents.
    /// </summary>
    [Fact]
    public void FixedTimeEquals()
    {
        Assert.True(Argon2.FixedTimeEquals(new byte[] { 1, 2 }, new byte[] { 1, 2 }));
        Assert.False(Argon2.FixedTimeEquals(new byte[] { 1, 2 }, new byte[] { 1, 3 }));
        Assert.False(Argon2.FixedTimeEquals(new byte[] { 1, 2 }, new byte[] { 1 }));
    }

    /// <summary>
    /// Arguments the API refuses up front.
    /// </summary>
    [Fact]
    public void ArgumentChecks()
    {
        Assert.Throws<ArgumentNullException>(() => new Argon2((Argon2Config)null!));
        Assert.Throws<ArgumentNullException>(() => new Argon2((Argon2Memory)null!));
        Assert.Throws<ArgumentNullException>(() => Argon2.Hash((string)null!, (string)null));
        Assert.Throws<ArgumentNullException>(() => Argon2.Hash((string)null!));
        string encoded = Argon2.Hash("password", timeCost: 1, memoryCost: 32);
        Assert.Throws<ArgumentNullException>(() => Argon2.Verify(encoded, (string)null!, (string)null));
        Assert.Throws<ArgumentNullException>(() => Argon2.Verify(encoded, (string)null!, null, 1));
        Assert.Throws<ArgumentNullException>(() => ((Argon2Config)null!).EncodeString(new byte[4]));
        Assert.Throws<ArgumentNullException>(() => ((Argon2Memory)null!).EncodeString(new byte[4]));
        Assert.Throws<ArgumentNullException>(() => Span<byte>.Empty.ToB64String());
        Assert.Throws<ArgumentNullException>(() => Argon2Memory.RequiredBlockCounts(null!));
        Assert.Throws<ArgumentException>(() => EncodeExtension.EncodeString(
            (Argon2Type)42, Argon2Version.Nineteen, 32, 1, 1, default, default, Salt, new byte[4]));

        using var memory = new Argon2Memory(Config(Argon2Type.HybridAddressing, Argon2Version.Nineteen), Argon2MemoryPolicy.NoShrink, null);
        memory.StartUse();
        Assert.Throws<InvalidOperationException>(() => memory.ShrinkMemoryPolicy = Argon2MemoryPolicy.Shrink);
        memory.EndUse();
    }

    /// <summary>
    /// Encoding stops at what it is given: no salt, or a salt and no hash.
    /// </summary>
    [Fact]
    public void EncodeWithoutSaltOrHash()
    {
        Assert.Equal(
            "$argon2i$v=19$m=32,t=1,p=1",
            EncodeExtension.EncodeString(Argon2Type.DataIndependentAddressing, Argon2Version.Nineteen, 32, 1, 1, default, default, default, default));
        string saltOnly = EncodeExtension.EncodeString(Argon2Type.DataDependentAddressing, Argon2Version.Sixteen, 32, 1, 1, default, default, Salt, default);
        Assert.EndsWith("$" + ((Span<byte>)Salt).ToB64String(), saltOnly);
    }

    /// <summary>
    /// Padding and odd lengths in the Base64 parts of an encoded string.
    /// </summary>
    [Fact]
    public void DecodeBase64Edges()
    {
        var config = new Argon2Config();
        Assert.True(config.DecodeString("$argon2id$v=19$m=32,t=1,p=1,data=AQI=$c29tZXNhbHRzb21lc2FsdA==", out var noHash));
        Assert.Null(noHash);
        Assert.Equal(new byte[] { 1, 2 }, config.AssociatedData);
        Assert.False(config.DecodeString("$argon2id$v=", out _));
        Assert.False(config.DecodeString("$argon2id$v=19$m=32,t=1,p=1$A", out _));
        Assert.False(config.DecodeString("$argon2id$v=19$m=32,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$AAAAA", out _));
    }

    private static Argon2Config Config(Argon2Type type, Argon2Version version) => new()
    {
        Type = type,
        Version = version,
        TimeCost = 1,
        MemoryCost = 32,
        Lanes = 2,
        Threads = 2,
        HashLength = 20,
        Password = Encoding.UTF8.GetBytes("password"),
        Salt = Salt,
    };
}
