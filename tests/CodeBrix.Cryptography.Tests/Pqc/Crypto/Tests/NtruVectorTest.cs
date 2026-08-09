using System.Collections.Generic;
using System.Linq;
using CodeBrix.Cryptography.Asn1.Oiw;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Utilities;
using CodeBrix.Cryptography.Pqc.Crypto.Ntru;
using CodeBrix.Cryptography.Pqc.Crypto.Utilities;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Encoders;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Pqc.Crypto.Tests; //was previously: Org.BouncyCastle.Pqc.Crypto.Tests;

/// <remarks>
/// The fixtures these tests read live only in BouncyCastle's external bc-test-data
/// repository, which carries no licence and so cannot be redistributed here. They are
/// skipped unless that repository is cloned as a SIBLING of CodeBrix.Cryptography and
/// CODEBRIX_CRYPTOGRAPHY_USE_BC_TEST_DATA=1 is set. See BcTestData.
/// </remarks>
public class NtruVectorTest
{
    private static readonly Dictionary<string, NtruParameters> Parameters = new Dictionary<string, NtruParameters>()
    {
        { "ntruhps2048509/PQCkemKAT_935.rsp", NtruParameters.NtruHps2048509 },
        { "ntruhps2048677/PQCkemKAT_1234.rsp", NtruParameters.NtruHps2048677 },
        { "ntruhps4096821/PQCkemKAT_1590.rsp", NtruParameters.NtruHps4096821 },
        { "ntruhps40961229/PQCkemKAT_2366.rsp", NtruParameters.NtruHps40961229 },
        { "ntruhrss701/PQCkemKAT_1450.rsp", NtruParameters.NtruHrss701 },
        { "ntruhrss1373/PQCkemKAT_2983.rsp", NtruParameters.NtruHrss1373 },
    };

    [Fact]
    public void TestParameters()
    {
        Assert.Equal(256, NtruParameters.NtruHps2048509.DefaultKeySize);
        Assert.Equal(256, NtruParameters.NtruHps2048677.DefaultKeySize);
        Assert.Equal(256, NtruParameters.NtruHps4096821.DefaultKeySize);
        Assert.Equal(256, NtruParameters.NtruHps40961229.DefaultKeySize);
        Assert.Equal(256, NtruParameters.NtruHrss701.DefaultKeySize);
        Assert.Equal(256, NtruParameters.NtruHrss1373.DefaultKeySize);
    }

    public static IEnumerable<object[]> TestVectorFiles_Data => TestVectorFiles.Select(v => new object[] { v });

    private static readonly IEnumerable<string> TestVectorFiles = Parameters.Keys;

    [Fact]
    public void TestPrivInfoGeneration()
    {
        SecureRandom random = new SecureRandom();
        PqcOtherInfoGenerator.PartyU partyU = new PqcOtherInfoGenerator.PartyU(NtruParameters.NtruHrss701,
            new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1), Hex.Decode("beef"), Hex.Decode("cafe"), random);
        byte[] partA = partyU.GetSuppPrivInfoPartA();
        PqcOtherInfoGenerator.PartyV partyV = new PqcOtherInfoGenerator.PartyV(NtruParameters.NtruHrss701,
            new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1), Hex.Decode("beef"), Hex.Decode("cafe"), random);
        byte[] partB = partyV.GetSuppPrivInfoPartB(partA);
        DerOtherInfo otherInfoU = partyU.Generate(partB);
        DerOtherInfo otherInfoV = partyV.Generate();
        Assert.True(Arrays.AreEqual(otherInfoU.GetEncoded(), otherInfoV.GetEncoded()));
    }

    [Theory(Skip = BcTestData.SkipReason, SkipUnless = nameof(BcTestData.IsAvailable), SkipType = typeof(BcTestData))]
    [MemberData(nameof(TestVectorFiles_Data))]
    public void TV(string testVectorPath) =>
        PqcTestUtilities.RunTestVectors("pqc/crypto/ntru", testVectorPath, sampleOnly: true, RunTestVector);

    private static void RunTestVector(string path, Dictionary<string, string> data)
    {
        string count = data["count"];
        byte[] seed = Hex.Decode(data["seed"]);
        byte[] pk = Hex.Decode(data["pk"]);
        byte[] ct = Hex.Decode(data["ct"]);
        byte[] sk = Hex.Decode(data["sk"]);
        byte[] ss = Hex.Decode(data["ss"]);

        NistSecureRandom random = new NistSecureRandom(seed, null);
        NtruParameters ntruParameters = Parameters[path];

        // Test keygen
        NtruKeyGenerationParameters keygenParameters =
            new NtruKeyGenerationParameters(random, ntruParameters);

        NtruKeyPairGenerator keygen = new NtruKeyPairGenerator();
        keygen.Init(keygenParameters);
        AsymmetricCipherKeyPair keyPair = keygen.GenerateKeyPair();

        NtruPublicKeyParameters pubParams = (NtruPublicKeyParameters)keyPair.Public;
        NtruPrivateKeyParameters privParams = (NtruPrivateKeyParameters)keyPair.Private;

        Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), $"{path} {count} : public key");
        Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), $"{path} {count} : private key");

        var publicKeyRT = (NtruPublicKeyParameters)PqcPublicKeyFactory.CreateKey(
            PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubParams));
        var privateKeyRT = (NtruPrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(
            PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(privParams));

        Assert.True(Arrays.AreEqual(pk, publicKeyRT.GetEncoded()), $"{path} {count} : public key (round-trip)");
        Assert.True(Arrays.AreEqual(sk, privateKeyRT.GetEncoded()), $"{path} {count} : private key (round-trip)");

        // Test encapsulate
        NtruKemGenerator encapsulator = new NtruKemGenerator(random);
        ISecretWithEncapsulation encapsulation = encapsulator.GenerateEncapsulated(
            NtruPublicKeyParameters.FromEncoding(ntruParameters, pk));
        byte[] generatedSecret = encapsulation.GetSecret();
        byte[] generatedCiphertext = encapsulation.GetEncapsulation();

        Assert.Equal(generatedSecret.Length, ntruParameters.DefaultKeySize / 8);
        Assert.True(Arrays.AreEqual(ss, generatedSecret), $"{path} {count} : generated secret");
        Assert.True(Arrays.AreEqual(ct, generatedCiphertext), $"{path} {count} : ciphertext");

        // Test decapsulate
        NtruKemExtractor decapsulator = new NtruKemExtractor(
            NtruPrivateKeyParameters.FromEncoding(ntruParameters, sk));
        byte[] extractedSecret = decapsulator.ExtractSecret(ct);
        Assert.True(Arrays.AreEqual(ss, extractedSecret), $"{path} {count} : extracted secret");
    }
}
