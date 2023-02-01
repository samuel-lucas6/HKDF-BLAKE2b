using System.Security.Cryptography;
using Geralt;

namespace HkdfBlake2bDotNet;

public static class HkdfBlake2b
{
    public const int HashSize = BLAKE2b.MaxHashSize;
    
    public static void DeriveKey(Span<byte> okm, ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> info = default, ReadOnlySpan<byte> salt = default)
    {
        Span<byte> prk = stackalloc byte[HashSize];
        Extract(prk, ikm, salt);
        Expand(okm, prk, info);
    }

    public static void Extract(Span<byte> prk, ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt = default)
    {
        Validation.EqualToSize(nameof(prk), prk.Length, HashSize);
        Validation.NotEmpty(nameof(ikm), ikm.Length);
        Validation.SizeBetween(nameof(salt), salt.Length, minSize: 0, BLAKE2b.MaxKeySize);
        
        Span<byte> s = stackalloc byte[HashSize]; s.Clear();
        if (salt.Length > 0) {
            salt.CopyTo(s);
        }
        BLAKE2b.ComputeTag(prk, ikm, s);
        CryptographicOperations.ZeroMemory(s);
    }

    public static void Expand(Span<byte> okm, ReadOnlySpan<byte> prk, ReadOnlySpan<byte> info = default)
    {
        Validation.SizeBetween(nameof(okm), okm.Length, minSize: 1, HashSize * 255);
        Validation.SizeBetween(nameof(prk), prk.Length, BLAKE2b.MinKeySize, BLAKE2b.MaxKeySize);
        
        Span<byte> previousHash = stackalloc byte[HashSize];
        Span<byte> counter = stackalloc byte[1] { 0x01 };
        for (int i = 0; i < okm.Length; i += HashSize) {
            using var blake2b = new IncrementalBLAKE2b(HashSize, prk);
            blake2b.Update(i == 0 ? Span<byte>.Empty : previousHash);
            blake2b.Update(info);
            blake2b.Update(counter);
            blake2b.Finalize(previousHash);
            if (i + HashSize <= okm.Length) {
                previousHash.CopyTo(okm.Slice(i, previousHash.Length));
            } else {
                previousHash[..(okm.Length - i)].CopyTo(okm.Slice(i, okm.Length - i));
            }
            counter[0]++;
        }
        CryptographicOperations.ZeroMemory(previousHash);
    }
}