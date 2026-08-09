using System;
using System.IO;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Pkcs;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Crypto.IO;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Crypto.Utilities;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Crypto.Operators; //was previously: Org.BouncyCastle.Crypto.Operators;

public class Asn1CipherBuilderWithKey
    : ICipherBuilderWithKey
{
    private readonly KeyParameter m_cipherKey;
    private readonly AlgorithmIdentifier m_cipherAlgID;
    private readonly ICipherParameters m_cipherParameters;

    public Asn1CipherBuilderWithKey(DerObjectIdentifier encryptionOID, int keySize, SecureRandom random)
    {
        random = CryptoServicesRegistrar.GetSecureRandom(random);

        CipherKeyGenerator cipherKeyGen = GeneratorUtilities.GetKeyGenerator(encryptionOID);
        if (keySize < 0)
        {
            keySize = cipherKeyGen.DefaultStrength;
        }
        cipherKeyGen.Init(new KeyGenerationParameters(random, keySize));
        byte[] cipherKeyBytes = cipherKeyGen.GenerateKey();
        m_cipherKey = ParameterUtilities.CreateKeyParameter(encryptionOID, cipherKeyBytes);

        Asn1Encodable asn1Params = ImplGenerateAsn1Parameters(random, encryptionOID.GetID(), cipherKeyBytes);
        m_cipherAlgID = ImplGetAlgorithmIdentifier(encryptionOID.GetID(), m_cipherKey, asn1Params,
            out var cipherParameters);
        m_cipherParameters = new ParametersWithRandom(cipherParameters, random);
    }

    public object AlgorithmDetails => m_cipherAlgID;

    public int GetMaxOutputSize(int inputLen) => throw new NotImplementedException();

    public ICipher BuildCipher(Stream stream)
    {
        IBufferedCipher writeCipher = CipherUtilities.GetCipher(m_cipherAlgID.Algorithm);
        writeCipher.Init(forEncryption: true, m_cipherParameters);
        return new BufferedCipherWrapper(writeCipher, stream);
    }

    public ICipherParameters Key => m_cipherKey;

    internal static Asn1Encodable ImplGenerateAsn1Parameters(SecureRandom random, string encryptionOid,
        byte[] encKeyBytes)
    {
        try
        {
            if (PkcsObjectIdentifiers.RC2Cbc.GetID().Equals(encryptionOid))
            {
                byte[] iv = new byte[8];
                random.NextBytes(iv);

                int effectiveKeyBits = encKeyBytes.Length * 8;
                int parameterVersion = RC2CbcUtilities.GetParameterVersion(effectiveKeyBits);

                return new RC2CbcParameter(parameterVersion, iv);
            }

            return ParameterUtilities.GenerateParameters(encryptionOid, random);
        }
        catch (SecurityUtilityException)
        {
            // TODO Add a TryGenerateParameters or similar method on ParameterUtilities to avoid exceptions
            return null;
        }
    }

    internal static AlgorithmIdentifier ImplGetAlgorithmIdentifier(string encryptionOid,
        KeyParameter encKey, Asn1Encodable asn1Params, out ICipherParameters cipherParameters)
    {
        Asn1Object asn1Object;
        if (asn1Params != null)
        {
            asn1Object = asn1Params.ToAsn1Object();
            // TODO[cms] We'd prefer not to have to force Asn1Object conversion to call this
            cipherParameters = ParameterUtilities.GetCipherParameters(encryptionOid, encKey, asn1Object);
        }
        else
        {
            // TODO[cms] Should this be NoParams depending on the encryption algorithm?
            asn1Object = DerNull.Instance;
            cipherParameters = encKey;
        }

        return new AlgorithmIdentifier(new DerObjectIdentifier(encryptionOid), asn1Object);
    }
}

public class BufferedCipherWrapper
    : ICipher
{
    private readonly IBufferedCipher m_bufferedCipher;
    private readonly CipherStream m_stream;

    public BufferedCipherWrapper(IBufferedCipher bufferedCipher, Stream source)
    {
        m_bufferedCipher = bufferedCipher;
        m_stream = new CipherStream(source, bufferedCipher, bufferedCipher);
    }

    public int GetMaxOutputSize(int inputLen) => m_bufferedCipher.GetOutputSize(inputLen);

    public int GetUpdateOutputSize(int inputLen) => m_bufferedCipher.GetUpdateOutputSize(inputLen);

    public Stream Stream => m_stream;
}
