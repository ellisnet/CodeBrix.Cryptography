using System;
using CodeBrix.Cryptography.Crypto;

namespace CodeBrix.Cryptography.Crypto.Parameters; //was previously: Org.BouncyCastle.Crypto.Parameters;

/**
* parameters for Key derivation functions for ISO-18033
*/
public class Iso18033KdfParameters
	: IDerivationParameters
{
	byte[]  seed;

	public Iso18033KdfParameters(
		byte[]  seed)
	{
		this.seed = seed;
	}

	public byte[] GetSeed()
	{
		return seed;
	}
}
