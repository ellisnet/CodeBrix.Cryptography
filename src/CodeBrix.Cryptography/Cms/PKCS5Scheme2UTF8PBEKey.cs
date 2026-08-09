using System;
using CodeBrix.Cryptography.Asn1.Pkcs;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.Generators;
using CodeBrix.Cryptography.Crypto.Parameters;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

/**
 * PKCS5 scheme-2 - password converted to bytes using UTF-8.
 */
public class Pkcs5Scheme2Utf8PbeKey
	: CmsPbeKey
{
	public Pkcs5Scheme2Utf8PbeKey(
		char[]	password,
		byte[]	salt,
		int		iterationCount)
		: base(password, salt, iterationCount)
	{
	}

	public Pkcs5Scheme2Utf8PbeKey(
		char[]				password,
		AlgorithmIdentifier keyDerivationAlgorithm)
		: base(password, keyDerivationAlgorithm)
	{
	}

    public Pkcs5Scheme2Utf8PbeKey(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, int iterationCount)
        : base(password, salt, iterationCount)
    {
    }

    public Pkcs5Scheme2Utf8PbeKey(ReadOnlySpan<char> password, AlgorithmIdentifier keyDerivationAlgorithm)
        : base(password, keyDerivationAlgorithm)
    {
    }

    internal override KeyParameter GetEncoded(
		string algorithmOid)
	{
		Pkcs5S2ParametersGenerator gen = new Pkcs5S2ParametersGenerator();

		gen.Init(
			PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(password),
			salt,
			iterationCount);

		return (KeyParameter) gen.GenerateDerivedParameters(
			algorithmOid,
			CmsEnvelopedHelper.GetKeySize(algorithmOid));
	}
}
