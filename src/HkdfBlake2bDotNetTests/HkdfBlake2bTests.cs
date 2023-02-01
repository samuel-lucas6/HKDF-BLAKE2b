using Microsoft.VisualStudio.TestTools.UnitTesting;
using HkdfBlake2bDotNet;

namespace HkdfBlake2bDotNetTests;

[TestClass]
public class HkdfBlake2bTests
{
    // https://www.rfc-editor.org/rfc/rfc5869#appendix-A
    [TestMethod]
    [DataRow("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", "ddb46ab9050c91967148ae962c11245d293b6815f641b953dd725837e8414917b7532cbf0dc20b2710ad9104959043a64644c8ba25d14fece5dca080288f14a6", "f4753c772c3271b14b96fafcc7db243517f25954137667edc52aa6042bae7250b931295dbb81258482cd")]
    [DataRow("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f", "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "4c601a70088b9bdc87a2b8b0a44e41b5d512d06cd782688263d9aa219ee48f7e6bcf796ba242b9c168ef3920d0246ba236720489b3f29526f924ab80d02fc5c8", "ee497dd4b79ca8d9fc66e8a8c51dfad6cc397bc9a8f35bf146b8b79a45cd9dfcea870b206e0f5191f8f262f0d96d8ce457ea9294dc62c7400063d4d50699687c4aa0d37fe8c432a7dc19b9079e6d2d5d561e")]
    [DataRow("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "", "312852be4511209c77dfe98dcc3773d5b2de9cc8020ab3da65600c2b93cf3182da95f35a7941a8f8ec6500f81ba66c07249e68af9e4e1aebf31815a67a9e30d3", "0aad709babc52bc04596ee1d80741a999a0828c95c38faeda79c984961d6b5ec50805e48bc7065d24f2f")]
    public void TestVectors(string inputKeyingMaterial, string salt, string info, string pseudorandomKey, string outputKeyingMaterial)
    {
        Span<byte> prk = stackalloc byte[HkdfBlake2b.HashSize];
        Span<byte> okm = stackalloc byte[outputKeyingMaterial.Length / 2];
        
        Span<byte> ikm = Convert.FromHexString(inputKeyingMaterial);
        Span<byte> s = Convert.FromHexString(salt);
        Span<byte> i = Convert.FromHexString(info);
        
        HkdfBlake2b.Extract(prk, ikm, s);
        HkdfBlake2b.DeriveKey(okm, ikm, i, s);
        
        Assert.AreEqual(pseudorandomKey, Convert.ToHexString(prk).ToLower());
        Assert.AreEqual(outputKeyingMaterial, Convert.ToHexString(okm).ToLower());
    }
}