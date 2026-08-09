using System;
using CodeBrix.Cryptography.Bcpg.Sig;
using CodeBrix.Cryptography.Utilities.Test;
using Xunit;

namespace CodeBrix.Cryptography.Bcpg.OpenPgp.Tests; //was previously: Org.BouncyCastle.Bcpg.OpenPgp.Tests;

public class PgpFeaturesTest
    : SimpleTest
{
    public override void PerformTest()
    {
        Features f = new Features(true, Features.FEATURE_MODIFICATION_DETECTION);
        Assert.True(f.SupportsFeature(Features.FEATURE_MODIFICATION_DETECTION));
        Assert.True(f.SupportsModificationDetection);
        Assert.True(!f.SupportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));

        f = new Features(true, Features.FEATURE_VERSION_5_PUBLIC_KEY);
        Assert.True(!f.SupportsModificationDetection);
        Assert.True(f.SupportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));

        f = new Features(true, Features.FEATURE_AEAD_ENCRYPTED_DATA);
        Assert.True(f.SupportsFeature(Features.FEATURE_AEAD_ENCRYPTED_DATA));
        Assert.True(!f.SupportsModificationDetection);
        Assert.True(!f.SupportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));

        f = new Features(true, Features.FEATURE_AEAD_ENCRYPTED_DATA | Features.FEATURE_MODIFICATION_DETECTION);
        Assert.True(f.SupportsFeature(Features.FEATURE_AEAD_ENCRYPTED_DATA));
        Assert.True(f.SupportsModificationDetection);
        Assert.True(!f.SupportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));

        f = new Features(true, Features.FEATURE_VERSION_5_PUBLIC_KEY | Features.FEATURE_MODIFICATION_DETECTION);
        Assert.True(!f.SupportsFeature(Features.FEATURE_AEAD_ENCRYPTED_DATA));
        Assert.True(f.SupportsModificationDetection);
        Assert.True(f.SupportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));
    }

    public override string Name
    {
        get { return "PgpFeaturesTest"; }
    }

    [Fact]
    public void TestFunction()
    {
        string resultText = Perform().ToString();

        Assert.Equal(Name + ": Okay", resultText);
    }
}
