using System;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Cms;
using CodeBrix.Cryptography.Asn1.Pkcs;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Utilities;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

internal class PasswordRecipientInfoGenerator
	: RecipientInfoGenerator
{
	private AlgorithmIdentifier	keyDerivationAlgorithm;
	private KeyParameter		keyEncryptionKey;
	// TODO Can get this from keyEncryptionKey?
	private string				keyEncryptionKeyOID;

	internal PasswordRecipientInfoGenerator()
	{
	}

	internal AlgorithmIdentifier KeyDerivationAlgorithm
	{
		set { this.keyDerivationAlgorithm = value; }
	}

	internal KeyParameter KeyEncryptionKey
	{
		set { this.keyEncryptionKey = value; }
	}

	internal string KeyEncryptionKeyOID
	{
		set { this.keyEncryptionKeyOID = value; }
	}

	public RecipientInfo Generate(KeyParameter contentEncryptionKey, SecureRandom random)
	{
		byte[] keyBytes = contentEncryptionKey.GetKey();

		string rfc3211WrapperName = CmsEnvelopedHelper.GetRfc3211WrapperName(keyEncryptionKeyOID);
		IWrapper keyWrapper = WrapperUtilities.GetWrapper(rfc3211WrapperName);

		// Note: In Java build, the IV is automatically generated in JCE layer
		int ivLength = Platform.StartsWithIgnoreCase(rfc3211WrapperName, "DES") ? 8 : 16;

        var parametersWithIV = ParametersWithIV.Create(keyEncryptionKey, ivLength, random,
            (bytes, random) => random.NextBytes(bytes));

        keyWrapper.Init(true, new ParametersWithRandom(parametersWithIV, random));
    	Asn1OctetString encryptedKey = new DerOctetString(
			keyWrapper.Wrap(keyBytes, 0, keyBytes.Length));

		DerSequence seq = new DerSequence(
			new DerObjectIdentifier(keyEncryptionKeyOID),
            new DerOctetString(parametersWithIV.InternalIV)
        );

		AlgorithmIdentifier keyEncryptionAlgorithm = new AlgorithmIdentifier(
			PkcsObjectIdentifiers.IdAlgPwriKek, seq);

		return new RecipientInfo(new PasswordRecipientInfo(
			keyDerivationAlgorithm, keyEncryptionAlgorithm, encryptedKey));
	}
}
