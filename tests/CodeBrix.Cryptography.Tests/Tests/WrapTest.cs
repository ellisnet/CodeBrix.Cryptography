using System;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Math;
using CodeBrix.Cryptography.Pkcs;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Tests; //was previously: Org.BouncyCastle.Tests;

public class WrapTest
	: ITest
{
	public ITestResult Perform()
	{
		try
		{
//				IBufferedCipher cipher = CipherUtilities.GetCipher("DES/ECB/PKCS5Padding");
			IWrapper cipher = WrapperUtilities.GetWrapper("DES/ECB/PKCS5Padding");

			IAsymmetricCipherKeyPairGenerator fact = GeneratorUtilities.GetKeyPairGenerator("RSA");
			fact.Init(
				new RsaKeyGenerationParameters(
					BigInteger.ValueOf(0x10001),
					new SecureRandom(),
					512,
					25));

			AsymmetricCipherKeyPair keyPair = fact.GenerateKeyPair();

			AsymmetricKeyParameter priKey = keyPair.Private;
			AsymmetricKeyParameter pubKey = keyPair.Public;

			byte[] priKeyBytes = PrivateKeyInfoFactory.CreatePrivateKeyInfo(priKey).GetDerEncoded();

			CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator("DES");

//				Key wrapKey = keyGen.generateKey();
			byte[] wrapKeyBytes = keyGen.GenerateKey();
			KeyParameter wrapKey = new DesParameters(wrapKeyBytes);

//				cipher.Init(IBufferedCipher.WRAP_MODE, wrapKey);
			cipher.Init(true, wrapKey);
//				byte[] wrappedKey = cipher.Wrap(priKey);
			byte[] wrappedKey = cipher.Wrap(priKeyBytes, 0, priKeyBytes.Length);

//				cipher.Init(IBufferedCipher.UNWRAP_MODE, wrapKey);
			cipher.Init(false, wrapKey);

//				Key key = cipher.unwrap(wrappedKey, "RSA", IBufferedCipher.PRIVATE_KEY);
			byte[] unwrapped = cipher.Unwrap(wrappedKey, 0, wrappedKey.Length);

			//if (!Arrays.AreEqual(priKey.getEncoded(), key.getEncoded()))
			if (!Arrays.AreEqual(priKeyBytes, unwrapped))
			{
				return new SimpleTestResult(false, "Unwrapped key does not match");
			}

			return new SimpleTestResult(true, Name + ": Okay");
		}
		catch (Exception e)
		{
			return new SimpleTestResult(false, Name + ": exception - " + e.ToString());
		}
	}

	public string Name
	{
		get { return "WrapTest"; }
	}

	[Fact]
	public void TestFunction()
	{
		string resultText = Perform().ToString();

		Assert.Equal(Name + ": Okay", resultText);
	}
}
