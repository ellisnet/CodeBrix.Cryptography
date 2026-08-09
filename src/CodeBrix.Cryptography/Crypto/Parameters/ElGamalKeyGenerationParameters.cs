using System;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Crypto.Parameters; //was previously: Org.BouncyCastle.Crypto.Parameters;

public class ElGamalKeyGenerationParameters
	: KeyGenerationParameters
{
    private readonly ElGamalParameters parameters;

	public ElGamalKeyGenerationParameters(
        SecureRandom		random,
        ElGamalParameters	parameters)
		: base(random, GetStrength(parameters))
    {
        this.parameters = parameters;
    }

	public ElGamalParameters Parameters
    {
        get { return parameters; }
    }

	internal static int GetStrength(
		ElGamalParameters parameters)
	{
		return parameters.L != 0 ? parameters.L : parameters.P.BitLength;
	}
}
