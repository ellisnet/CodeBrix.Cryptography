using System;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Pkcs;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Pqc.Asn1;
using CodeBrix.Cryptography.Pqc.Crypto.Bike;
using CodeBrix.Cryptography.Pqc.Crypto.Cmce;
using CodeBrix.Cryptography.Pqc.Crypto.Crystals.Dilithium;
using CodeBrix.Cryptography.Pqc.Crypto.Falcon;
using CodeBrix.Cryptography.Pqc.Crypto.Frodo;
using CodeBrix.Cryptography.Pqc.Crypto.Hqc;
using CodeBrix.Cryptography.Pqc.Crypto.Lms;
using CodeBrix.Cryptography.Pqc.Crypto.Ntru;
using CodeBrix.Cryptography.Pqc.Crypto.Picnic;
using CodeBrix.Cryptography.Pqc.Crypto.Saber;
using CodeBrix.Cryptography.Pqc.Crypto.SphincsPlus;
using CodeBrix.Cryptography.Utilities;

namespace CodeBrix.Cryptography.Pqc.Crypto.Utilities; //was previously: Org.BouncyCastle.Pqc.Crypto.Utilities;

/// <summary>
/// A factory to produce Public Key Info Objects.
/// </summary>
public static class PqcSubjectPublicKeyInfoFactory
{
    /// <summary>
    /// Create a Subject Public Key Info object for a given public key.
    /// </summary>
    /// <param name="publicKey">One of ElGammalPublicKeyParameters, DSAPublicKeyParameter, DHPublicKeyParameters, RsaKeyParameters or ECPublicKeyParameters</param>
    /// <returns>A subject public key info object.</returns>
    /// <exception cref="Exception">Throw exception if object provided is not one of the above.</exception>
    public static SubjectPublicKeyInfo CreateSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
    {
        if (publicKey == null)
            throw new ArgumentNullException("publicKey");
        if (publicKey.IsPrivate)
            throw new ArgumentException("Private key passed - public key expected.", "publicKey");

        if (publicKey is LmsPublicKeyParameters lmsPublicKeyParameters)
        {
            byte[] encoding = Composer.Compose().U32Str(1).Bytes(lmsPublicKeyParameters).Build();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdAlgHssLmsHashsig);
            return new SubjectPublicKeyInfo(algorithmIdentifier, encoding);
        }
        if (publicKey is HssPublicKeyParameters hssPublicKeyParameters)
        {
            int L = hssPublicKeyParameters.Level;
            byte[] encoding = Composer.Compose().U32Str(L).Bytes(hssPublicKeyParameters.LmsPublicKey).Build();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdAlgHssLmsHashsig);
            return new SubjectPublicKeyInfo(algorithmIdentifier, encoding);
        }
#pragma warning disable CS0618 // Type or member is obsolete
        if (publicKey is SphincsPlusPublicKeyParameters sphincsPlusPublicKeyParameters)
        {
            byte[] encoding = sphincsPlusPublicKeyParameters.GetEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                PqcUtilities.SphincsPlusOidLookup(sphincsPlusPublicKeyParameters.Parameters));
            return new SubjectPublicKeyInfo(algorithmIdentifier, encoding);
        }
#pragma warning restore CS0618 // Type or member is obsolete
        if (publicKey is CmcePublicKeyParameters cmcePublicKeyParameters)
        {
            byte[] encoding = cmcePublicKeyParameters.GetEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                PqcUtilities.McElieceOidLookup(cmcePublicKeyParameters.Parameters));

            // https://datatracker.ietf.org/doc/draft-uni-qsckeys/
            return new SubjectPublicKeyInfo(algorithmIdentifier, new CmcePublicKey(encoding));
        }
        else if (publicKey is FrodoPublicKeyParameters frodoPublicKeyParameters)
        {
            byte[] encoding = frodoPublicKeyParameters.GetEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                PqcUtilities.FrodoOidLookup(frodoPublicKeyParameters.Parameters));

            return new SubjectPublicKeyInfo(algorithmIdentifier, new DerOctetString(encoding));
        }
        if (publicKey is SaberPublicKeyParameters saberPublicKeyParameters)
        {
            byte[] encoding = saberPublicKeyParameters.GetEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                PqcUtilities.SaberOidLookup(saberPublicKeyParameters.Parameters));

            // https://datatracker.ietf.org/doc/draft-uni-qsckeys/
            return new SubjectPublicKeyInfo(algorithmIdentifier, new DerSequence(new DerOctetString(encoding)));
        }
        if (publicKey is PicnicPublicKeyParameters picnicPublicKeyParameters)
        {
            byte[] encoding = picnicPublicKeyParameters.GetEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                PqcUtilities.PicnicOidLookup(picnicPublicKeyParameters.Parameters));
            return new SubjectPublicKeyInfo(algorithmIdentifier, new DerOctetString(encoding));
        }
        if (publicKey is FalconPublicKeyParameters falconPublicKeyParameters)
        {
            byte[] keyEnc = falconPublicKeyParameters.GetEncoded();

            byte[] encoding = new byte[keyEnc.Length + 1];
            encoding[0] = (byte)(0x00 + falconPublicKeyParameters.Parameters.LogN);
            Array.Copy(keyEnc, 0, encoding, 1, keyEnc.Length);

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                PqcUtilities.FalconOidLookup(falconPublicKeyParameters.Parameters));
            return new SubjectPublicKeyInfo(algorithmIdentifier, encoding);
        }
#pragma warning disable CS0618 // Type or member is obsolete
        if (publicKey is DilithiumPublicKeyParameters dilithiumPublicKeyParameters)
        {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                PqcUtilities.DilithiumOidLookup(dilithiumPublicKeyParameters.Parameters));

            return new SubjectPublicKeyInfo(algorithmIdentifier, dilithiumPublicKeyParameters.GetEncoded());
        }
#pragma warning restore CS0618 // Type or member is obsolete
        if (publicKey is BikePublicKeyParameters bikePublicKeyParameters)
        {
            byte[] encoding = bikePublicKeyParameters.GetEncoded();
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                PqcUtilities.BikeOidLookup(bikePublicKeyParameters.Parameters));

            return new SubjectPublicKeyInfo(algorithmIdentifier, encoding);
        }
        if (publicKey is HqcPublicKeyParameters hqcPublicKeyParameters)
        {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                PqcUtilities.HqcOidLookup(hqcPublicKeyParameters.Parameters));
            return new SubjectPublicKeyInfo(algorithmIdentifier,
                publicKey: new DerBitString(hqcPublicKeyParameters.InternalPublicKey));
        }
        if (publicKey is NtruPublicKeyParameters ntruPublicKeyParameters)
        {
            byte[] encoding = ntruPublicKeyParameters.GetEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                PqcUtilities.NtruOidLookup(ntruPublicKeyParameters.Parameters));
            return new SubjectPublicKeyInfo(algorithmIdentifier, encoding);
        }

        throw new ArgumentException("Class provided no convertible: " + Platform.GetTypeName(publicKey));
    }
}
