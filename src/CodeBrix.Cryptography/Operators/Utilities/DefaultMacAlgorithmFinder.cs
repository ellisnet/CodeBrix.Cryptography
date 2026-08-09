using System;
using System.Collections.Generic;
using CodeBrix.Cryptography.Asn1;
using CodeBrix.Cryptography.Asn1.Nist;
using CodeBrix.Cryptography.Asn1.Oiw;
using CodeBrix.Cryptography.Asn1.Pkcs;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Utilities.Collections;

namespace CodeBrix.Cryptography.Operators.Utilities; //was previously: Org.BouncyCastle.Operators.Utilities;

public class DefaultMacAlgorithmFinder
    : IMacAlgorithmFinder
{
    public static readonly DefaultMacAlgorithmFinder Instance = new DefaultMacAlgorithmFinder();

    private static readonly Dictionary<string, AlgorithmIdentifier> MacNameToAlgIDs =
        new Dictionary<string, AlgorithmIdentifier>(StringComparer.OrdinalIgnoreCase);

    static DefaultMacAlgorithmFinder()
    {
        MacNameToAlgIDs.Add("HMACSHA1", new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1));
        MacNameToAlgIDs.Add("HMACSHA224", new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha224, DerNull.Instance));
        MacNameToAlgIDs.Add("HMACSHA256", new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha256, DerNull.Instance));
        MacNameToAlgIDs.Add("HMACSHA384", new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha384, DerNull.Instance));
        MacNameToAlgIDs.Add("HMACSHA512", new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha512, DerNull.Instance));
        MacNameToAlgIDs.Add("HMACSHA512-224", new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha512_224, DerNull.Instance));
        MacNameToAlgIDs.Add("HMACSHA512-256", new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha512_256, DerNull.Instance));
        MacNameToAlgIDs.Add("HMACSHA3-224", new AlgorithmIdentifier(NistObjectIdentifiers.IdHMacWithSha3_224));
        MacNameToAlgIDs.Add("HMACSHA3-256", new AlgorithmIdentifier(NistObjectIdentifiers.IdHMacWithSha3_256));
        MacNameToAlgIDs.Add("HMACSHA3-384", new AlgorithmIdentifier(NistObjectIdentifiers.IdHMacWithSha3_384));
        MacNameToAlgIDs.Add("HMACSHA3-512", new AlgorithmIdentifier(NistObjectIdentifiers.IdHMacWithSha3_512));
    }

    protected DefaultMacAlgorithmFinder()
    {
    }

    public virtual AlgorithmIdentifier Find(string macName) =>
        CollectionUtilities.GetValueOrNull(MacNameToAlgIDs, macName);
}
