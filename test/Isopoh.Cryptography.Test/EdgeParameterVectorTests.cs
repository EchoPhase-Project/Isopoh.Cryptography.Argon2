// <copyright file="EdgeParameterVectorTests.cs" company="Isopoh">
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
/// Known answers for edge parameters, made with the C reference implementation
/// in Reference/ (and the same as the system argon2 command where it has the
/// options): the minimum memory (8 blocks per lane), memory that is not a
/// multiple of 4 * lanes, one pass, one lane, an empty password, the minimum
/// salt length, a secret and associated data longer than one and two BLAKE2b
/// blocks, tag lengths 4 and 1024, all three types, and both versions.
/// </summary>
/// <remarks>
/// To make a vector again, run (secret and associated data are the patterns
/// <see cref="Pattern"/> makes, from 'a' and 'A'):
/// <c>Reference/bin/Debug/argon2 SALT -i|-d|-id -x PASSWORD -t T -k M -p P -l TAGLENGTH -r -v 10|13 [-s SECRET] [-a AD]</c>.
/// </remarks>
public class EdgeParameterVectorTests
{
    /// <summary>
    /// Gets the vectors: name, type, version, time cost, memory cost (KiB),
    /// lanes, password, salt, secret length, associated data length, tag (hexadecimal).
    /// </summary>
    public static object[][] Vectors =>
        [
            new object[] { "lanes1-min-memory", Argon2Type.DataIndependentAddressing, Argon2Version.Nineteen, 1, 8, 1, "password", "somesalt", 0, 0, "cbf2bce47e6d23999626143fabc5db69164743ee000ddd3f8895a6f82cfb9a6e" },
            new object[] { "lanes1-min-memory-v16", Argon2Type.DataDependentAddressing, Argon2Version.Sixteen, 1, 8, 1, "password", "somesalt", 0, 0, "0a23a2261ba63dba51e84e611a6b0262017edff7e177428052a80ca405d915d7" },
            new object[] { "p2-min-memory", Argon2Type.DataDependentAddressing, Argon2Version.Nineteen, 2, 16, 2, "password", "somesalt", 0, 0, "59f20a66a4c31bf0438a2f494867c32120409a91380f0687aefee984ba86bda8" },
            new object[] { "p4-min-memory-v16", Argon2Type.HybridAddressing, Argon2Version.Sixteen, 1, 32, 4, "password", "somesalt", 0, 0, "80616c63a2cb383329817b1d2cbd94308561af7f7f018dec476905c4f9014593" },
            new object[] { "p2-m33", Argon2Type.HybridAddressing, Argon2Version.Nineteen, 2, 33, 2, "password", "somesalt", 0, 0, "0ac32e35f28b3e219900fff2e5a8d9f00bce8b9e4752b1fca712d78737d78acd" },
            new object[] { "p3-m100", Argon2Type.DataIndependentAddressing, Argon2Version.Sixteen, 2, 100, 3, "password", "somesalt", 0, 0, "90a379a4caffde97dc9b24a171685db2796ba340043dd4b50035c64f9050076d" },
            new object[] { "p3-m100-d", Argon2Type.DataDependentAddressing, Argon2Version.Nineteen, 1, 100, 3, "password", "somesalt", 0, 0, "4e439d43a9f0c3807ca61bb0d0495d53facc99e45097e4b8d6f964087bf29303" },
            new object[] { "t1-i", Argon2Type.DataIndependentAddressing, Argon2Version.Nineteen, 1, 64, 1, "password", "somesalt", 0, 0, "9bec782fb84dd994630417dc331dbd068e49749c48139d9daad33a23fc068c36" },
            new object[] { "empty-password-d", Argon2Type.DataDependentAddressing, Argon2Version.Nineteen, 2, 32, 1, string.Empty, "8bytesal", 0, 0, "50775bac38a9aad03946a117f687a1e1e5a49fc825761a06fb268ce4bf682011" },
            new object[] { "empty-password-id-v16", Argon2Type.HybridAddressing, Argon2Version.Sixteen, 1, 32, 2, string.Empty, "8bytesal", 0, 0, "e3d2affc8c26425f96e72462388be6559a2b7e85015ecf4fd3afad4119b6ac4b" },
            new object[] { "secret65-ad65", Argon2Type.HybridAddressing, Argon2Version.Nineteen, 2, 32, 1, "password", "somesalt", 65, 65, "b27e443cdaafa132b47992d3bd7656fc3cba3a855ba2ca8ec356d27591f585c7" },
            new object[] { "secret129-ad129-v16", Argon2Type.DataIndependentAddressing, Argon2Version.Sixteen, 1, 48, 2, "password", "somesalt", 129, 129, "0afff726a858ce1fc773ab04504172799c7acac973c1b2b015d4a8f43561cdf1" },
            new object[] { "secret200-ad300-d", Argon2Type.DataDependentAddressing, Argon2Version.Nineteen, 1, 24, 1, "password", "somesalt", 200, 300, "48b07407b2589b1c741ad8e78ca21e18233ff9f5899c37b2303b5318819eb63f" },
            new object[] { "tag4-d", Argon2Type.DataDependentAddressing, Argon2Version.Nineteen, 1, 32, 1, "password", "somesalt", 0, 0, "8de0cf2a" },
            new object[] { "tag4-i-v16", Argon2Type.DataIndependentAddressing, Argon2Version.Sixteen, 1, 16, 2, "password", "somesalt", 0, 0, "1e8598c8" },
            new object[] { "tag1024-id", Argon2Type.HybridAddressing, Argon2Version.Nineteen, 1, 64, 2, "password", "somesalt", 0, 0, "5a7e41d7440f7120de63bf5eb7db26d9af6ae18362906d9c1cdd0a5727974c7f0884d8112d18c0acb956597ef08f6ee929127f71785dca85947901aeedd7f5c6558ed0a018c23135fedeb517e8bee3429c4dfde23af9fac30f48f72379b73ec5fb9334bdd62c6c981626054511648f48dad8f97feb6bd8f230f75da9b48537b1c7dff7668ca037be5bd19760c8305b0a994efce5bc9967f81026033f07e38ae70ab4b188dbe27b14e59c11d08993dfe0be4fb0916483f67ca2a6510151db1851fe078c3c22685a6c14ff39b35dab2d393479135b9db18999f534aa368e8cc091eb65d90820151c2f41ca1e4a68ff63c847cfb40238597aea6b872f23a7d4f489d6cfcead5fa416cc54e440649a9423357dd937cee84fb3af60d4dd2acc3881393362db7cba305c3f67764bf647755a07d87340662ec0e5d5e3039050fb2d17fb08a2e4aa920f8d86d1a7cd231130faceafc8fb851dd9f6544a221f39e5ca844c0447da7fe226f19483fa8c5fe176bc016e227f2ef956b53e67b5e4d1c49d8a88860a4325e6099a68a81e8fbfcacafb8c4960192102a6a13428d7fcf5ca8033b4c8116ee49eb13871e44eeb9606d9e4d1e3c2b9cfd0d776763440e1e3e05af0c90f60107c625531c98c0cf630599b7b203029ffd739335a943db118ceb354d6adf748de224e5e1071989008f7b0ffd726ad0313f7ec3fb2d34009dcbfbaef2aa19092fb1b15f7207d27d537445c2344658e11377ab1ac88cde9cae8db9855536c43f83776e69a73db1a222732ae894d14279cb282baad06c463bbcd51bbf3a8e7858a671dda323636f6325fedcc9343e4828135f8f36bd4824935558634efaf3fef625202a30dcb24f062e65b9fc732ef46238289e3c626ad09154a89832a85ce878baee04e3097af865b255180bcb5f50c38f59c73155cf6f5a81381dfaffe05e5c4977141f181657d94ac5e7b8ccac380a3890b8ee670b5f54c4e95e9271c7ebde7b8dbf25d51fa2f44fd516b70d503970b06d0ea7f83c29cc2d03ebc1eb0b5ac42e9b74bedb51cda1c8caa335401fe6a565bd8e5d5ec68bcded24d811704ece612e795796967d457077eabe2a23db0d6ea9403298db138ed33cbee04bc50542bb4bd0449bd5d1988a3d1201f25e91a13cd4d4f08e7cd4aa6c256b2432116560a56fa40b2190647a2c3388c32c9364be902d77b1e43de6efc5371a07fa3d9aacfbcd619c0d1a33c5ba351e4237d6953a03736e4e58a7e18430c8bf303034e1216c94adc32b60c962fddec1907647b7ace86585e30c9f8520745298e2f6bf873185e76622740f5326332fd74bfeabcbae0f7e554c72968606c35b6db14580a2e66e4e15970b8bca28d18799e1920756a56f169d0a5f5a32ff64608ee6e90a859b16002baf27054391c71b178ce7a3b6e9165326179268eef0720f0b547473ada" },
            new object[] { "tag1024-d-v16-secret-ad", Argon2Type.DataDependentAddressing, Argon2Version.Sixteen, 2, 40, 1, "password", "somesalt", 129, 65, "8cde20ad57b9d99781c31160d010dbd02669fdf12c92c6f234c59093004485e05d760c692277b8a849a2f23ed54965add23ae7c72773423fc80483114b353f6b757b5b5c329262d0e07f40502c0e61f739b04969f0e2b6f194acaa72017ad81659e98aeac5abd6c499504c0998b162a8463c7075efba39b9bee4771e04abb22bc959b385155a61225153fd7382b5575620b51d18d64b76b026809626ea37a41e905903dd552367aa08ce1205174c5c40884b662dfb9b777dd90d0cbcc8ee56d2aa3f9f8809b39dfc17b0f260307b4ab194a81dad9a0e8c0f2904cea7994a7e6aac9a526bf1adef2a6ad997c1de96b43060e23f29a3c892d1079f6d0867a85077ee94e163e163df8e8644d9bf96811a6815643517e239d11075b6ccb09c4dd0f0eb8d29142d39a877e5ec855a9a3f2af94adf8ce4d0b0dbb0b2e28703ee7f4e36fba22ad9b2d28626cfd7a033472caed3bf2bbc576486df5340bd0d338fa98183aca7aaccf4abcb2ed97b68b49e259e0333f37ff2ff65d4c384434ca1fb0432a467d3fb5b0c4a69489c724b018b087a13093f002f80826b0c80d34586b2290d52336bd5d3d003477ce07dfdaadfa1fc685e5211cbef348c514d8dcd5c02c79408aeab4cc59b0b990db448f60aae9423aa3f2f9808ca1d597e94b6ecebd17f97805908b24c84221954719458b193f37f4c62a5ffc868c33fe8c49866f5766cae894b0afb8342c450bc5b10dd9f2fccb620fdc7390135c0adaca83b8a917d9bb12a3bfbe9cfa3d96a0ceacfb3135383397c971534738cc65597a3ab50810a72dc34c1a6edd9b2a2e8ec7f5c2aa6153fd51f74202043f1ec862e97b3baa530a5c9bff492b882c8a60624190c04d382fd1c42c075e33a5886b8d6dce24d5953404eb2cf04276f04dcc85f45236c140fd3e9366342023e08e6c539c6b8ac62a2a294a26810f25de176f38227162dd4183c152a66c4c3e13b067c7d34847919ef3381d23092e83bf8ada0cdc4eea700dda2bf31d54d0b49ce2a80f53d326ea7b44e699072a86d74930c69b30ce2eec1d459a65c4781f9dd3209f027024cff80f096bf1bd698394bbf814e8539418844a9df03e2d0ffd723bbe821026131f47527b04debe3c215149dded412e65789ca5497153681328ced76e0c3516d2241b6e21abdcb43a51b9a717061a502a8c092a293314ada0413ef53f0d47ad538d69d4ea8d67e1912fa3029d27fa5d17dedcb82c31e598f35478a091dd60e8ff34334abfa4cad88bbe8d2245ac49ff127fd76de8d27fcca7665836182c79a99a3408687503f8bdc58df6edce73e7a434f5720a9340420f67df3673943c655fda1eb127fa69b9c62fe3a9c60c4b45bd08203cd831c453b16728a140d3109328f324d0e7cb03f78b5f7f5b60df0cfd62a45f74bd5166aa5ef659261431e898c6dc98280c68838c2" },
        ];

    /// <summary>
    /// The raw hash is the reference hash, with one thread and with one thread per lane,
    /// and the encoded hash verifies.
    /// </summary>
    /// <param name="name">The name of the vector.</param>
    /// <param name="type">The Argon2 type.</param>
    /// <param name="version">The Argon2 version.</param>
    /// <param name="timeCost">The number of passes.</param>
    /// <param name="memoryCost">The memory cost in KiB.</param>
    /// <param name="lanes">The number of lanes.</param>
    /// <param name="password">The password.</param>
    /// <param name="salt">The salt.</param>
    /// <param name="secretLength">The length of the secret; 0 for none.</param>
    /// <param name="associatedDataLength">The length of the associated data; 0 for none.</param>
    /// <param name="expected">The expected tag in hexadecimal.</param>
    [Theory]
    [MemberData(nameof(Vectors))]
    public void MatchesReference(
        string name,
        Argon2Type type,
        Argon2Version version,
        int timeCost,
        int memoryCost,
        int lanes,
        string password,
        string salt,
        int secretLength,
        int associatedDataLength,
        string expected)
    {
        foreach (int threads in new[] { 1, lanes }.Distinct())
        {
            var config = new Argon2Config
            {
                Type = type,
                Version = version,
                TimeCost = timeCost,
                MemoryCost = memoryCost,
                Lanes = lanes,
                Threads = threads,
                Password = Encoding.ASCII.GetBytes(password),
                Salt = Encoding.ASCII.GetBytes(salt),
                Secret = secretLength == 0 ? null : Encoding.ASCII.GetBytes(Pattern('a', secretLength)),
                AssociatedData = associatedDataLength == 0 ? null : Encoding.ASCII.GetBytes(Pattern('A', associatedDataLength)),
                HashLength = expected.Length / 2,
                SecureArrayCall = SecureArray.DefaultCall,
            };

            string encoded;
            using (var argon2 = new Argon2(config))
            {
                Assert.True(
                    expected == Convert.ToHexString(argon2.Hash()).ToLowerInvariant(),
                    $"{name}: the hash with {threads} thread(s) is not the reference hash.");
                encoded = Argon2.Hash(config);
            }

            Assert.True(
                Argon2.Verify(encoded, config.Password, config.Secret, SecureArray.DefaultCall),
                $"{name}: {encoded} does not verify.");
        }
    }

    /// <summary>
    /// The same pattern as the generator of the vectors: 'a', 'b', ... 'z', 'a', ...
    /// </summary>
    /// <param name="first">The first character.</param>
    /// <param name="length">The length of the pattern.</param>
    /// <returns>The pattern.</returns>
    private static string Pattern(char first, int length) =>
        new(Enumerable.Range(0, length).Select(i => (char)(first + (i % 26))).ToArray());
}
