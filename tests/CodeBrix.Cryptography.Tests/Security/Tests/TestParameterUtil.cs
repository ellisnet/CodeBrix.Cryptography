using System;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Cms;
using CodeBrix.Cryptography.Asn1.Nist;
using CodeBrix.Cryptography.Asn1.Oiw;
using CodeBrix.Cryptography.Asn1.Pkcs;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Utilities;
using Xunit;

namespace CodeBrix.Cryptography.Security.Tests; //was previously: Org.BouncyCastle.Security.Tests;

public class TestParameterUtilities
{
	[Fact]
	public void TestCreateKeyParameter()
	{
		SecureRandom random = new SecureRandom();

		doTestCreateKeyParameter("AES", NistObjectIdentifiers.IdAes128Cbc,
			128, typeof(KeyParameter), random);
		doTestCreateKeyParameter("DES", OiwObjectIdentifiers.DesCbc,
			64, typeof(DesParameters), random);
		doTestCreateKeyParameter("DESEDE", PkcsObjectIdentifiers.DesEde3Cbc,
			192, typeof(DesEdeParameters), random);
		doTestCreateKeyParameter("RC2", PkcsObjectIdentifiers.RC2Cbc,
			128, typeof(RC2Parameters), random);
	}

    [Fact]
    public void TestGetCipherParameters()
    {
        var aes128Ccm = ParameterUtilities.GetCipherParameters(
            NistObjectIdentifiers.IdAes128Ccm,
            new KeyParameter(new byte[16]),
            new CcmParameters(new byte[12], 16).ToAsn1Object());
        Assert.IsAssignableFrom<AeadParameters>(aes128Ccm);

        var aes192Ccm = ParameterUtilities.GetCipherParameters(
            NistObjectIdentifiers.IdAes192Ccm,
            new KeyParameter(new byte[24]),
            new CcmParameters(new byte[12], 16).ToAsn1Object());
        Assert.IsAssignableFrom<AeadParameters>(aes192Ccm);

        var aes256Ccm = ParameterUtilities.GetCipherParameters(
            NistObjectIdentifiers.IdAes256Ccm,
            new KeyParameter(new byte[32]),
            new CcmParameters(new byte[12], 16).ToAsn1Object());
        Assert.IsAssignableFrom<AeadParameters>(aes256Ccm);

        var aes128Gcm = ParameterUtilities.GetCipherParameters(
            NistObjectIdentifiers.IdAes128Gcm,
            new KeyParameter(new byte[16]),
            new GcmParameters(new byte[12], 16).ToAsn1Object());
        Assert.IsAssignableFrom<AeadParameters>(aes128Gcm);

        var aes192Gcm = ParameterUtilities.GetCipherParameters(
            NistObjectIdentifiers.IdAes192Gcm,
            new KeyParameter(new byte[24]),
            new GcmParameters(new byte[12], 16).ToAsn1Object());
        Assert.IsAssignableFrom<AeadParameters>(aes192Gcm);

        var aes256Gcm = ParameterUtilities.GetCipherParameters(
			NistObjectIdentifiers.IdAes256Gcm,
			new KeyParameter(new byte[32]),
			new GcmParameters(new byte[12], 16).ToAsn1Object());
        Assert.IsAssignableFrom<AeadParameters>(aes256Gcm);
    }

    private void doTestCreateKeyParameter(
		string				algorithm,
		DerObjectIdentifier	oid,
		int					keyBits,
		Type				expectedType,
		SecureRandom		random)
	{
		int keyLength = keyBits / 8;
		byte[] bytes = new byte[keyLength];
		random.NextBytes(bytes);

		KeyParameter key;

		key = ParameterUtilities.CreateKeyParameter(algorithm, bytes);
		checkKeyParameter(key, expectedType, bytes);

		key = ParameterUtilities.CreateKeyParameter(oid, bytes);
		checkKeyParameter(key, expectedType, bytes);

		bytes = new byte[keyLength * 2];
		random.NextBytes(bytes);

		int offset = random.Next(1, keyLength);
		byte[] expected = new byte[keyLength];
		Array.Copy(bytes, offset, expected, 0, keyLength);

		key = ParameterUtilities.CreateKeyParameter(algorithm, bytes, offset, keyLength);
		checkKeyParameter(key, expectedType, expected);

		key = ParameterUtilities.CreateKeyParameter(oid, bytes, offset, keyLength);
		checkKeyParameter(key, expectedType, expected);
	}

	private void checkKeyParameter(
		KeyParameter	key,
		Type			expectedType,
		byte[]			expectedBytes)
	{
		Assert.True(expectedType.IsInstanceOfType(key));
		Assert.True(Arrays.AreEqual(expectedBytes, key.GetKey()));
	}
}
