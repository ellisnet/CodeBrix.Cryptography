using System;
using CodeBrix.Cryptography.Asn1.Cms;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

public interface RecipientInfoGenerator
{
	/// <summary>
	/// Generate a RecipientInfo object for the given key.
	/// </summary>
	/// <param name="contentEncryptionKey">
	/// A <see cref="KeyParameter"/>
	/// </param>
	/// <param name="random">
	/// A <see cref="SecureRandom"/>
	/// </param>
	/// <returns>
	/// A <see cref="RecipientInfo"/>
	/// </returns>
	/// <exception cref="GeneralSecurityException"></exception>
	RecipientInfo Generate(KeyParameter contentEncryptionKey, SecureRandom random);
}
