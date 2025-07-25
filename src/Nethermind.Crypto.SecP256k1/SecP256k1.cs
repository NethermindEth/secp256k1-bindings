// SPDX-FileCopyrightText: 2025 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Loader;
using System.Security.Cryptography;

namespace Nethermind.Crypto;

public static unsafe partial class SecP256k1
{
    private const string LibraryName = "secp256k1";

    /* constants from pycoin (https://github.com/richardkiss/pycoin)*/
    private const uint Secp256K1FlagsTypeMask = (1 << 8) - 1;
    private const uint Secp256K1FlagsTypeContext = 1 << 0;
    private const uint Secp256K1FlagsTypeCompression = 1 << 1;
    /* The higher bits contain the actual data. Do not use directly. */
    private const uint Secp256K1FlagsBitContextVerify = 1 << 8;
    private const uint Secp256K1FlagsBitContextSign = 1 << 9;
    private const uint Secp256K1FlagsBitCompression = 1 << 8;
    /* Flags to pass to secp256k1_context_create. */
    private const uint Secp256K1ContextVerify = Secp256K1FlagsTypeContext | Secp256K1FlagsBitContextVerify;
    private const uint Secp256K1ContextSign = Secp256K1FlagsTypeContext | Secp256K1FlagsBitContextSign;
    private const uint Secp256K1ContextNone = Secp256K1FlagsTypeContext;
    private const uint Secp256K1EcCompressed = Secp256K1FlagsTypeCompression | Secp256K1FlagsBitCompression;
    private const uint Secp256K1EcUncompressed = Secp256K1FlagsTypeCompression;

    private static readonly nint _context;

    static SecP256k1()
    {
        AssemblyLoadContext.Default.ResolvingUnmanagedDll += OnResolvingUnmanagedDll;

        _context = secp256k1_context_create(Secp256K1ContextSign | Secp256K1ContextVerify);

        Span<byte> seed = stackalloc byte[32];

        RandomNumberGenerator.Fill(seed);

        fixed (byte* ptr = &MemoryMarshal.GetReference(seed))
        {
            var result = secp256k1_context_randomize(_context, ptr);

            Debug.Assert(result == 1, "Context randomization failed");
        }
    }

    public static bool VerifyPrivateKey(ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length == 0)
            return false;

        fixed (byte* ptr = &MemoryMarshal.GetReference(privateKey))
            return secp256k1_ec_seckey_verify(_context, ptr) == 1;
    }

    public static byte[]? GetPublicKey(ReadOnlySpan<byte> privateKey, bool compressed)
    {
        if (privateKey.Length == 0)
            return null;

        Span<byte> output = stackalloc byte[compressed ? 33 : 65];
        byte* publicKey = stackalloc byte[64];

        fixed (byte* outputPtr = &MemoryMarshal.GetReference(output))
        fixed (byte* privateKeyPtr = &MemoryMarshal.GetReference(privateKey))
        {
            bool failed = secp256k1_ec_pubkey_create(_context, publicKey, privateKeyPtr) == 0;

            if (failed)
                return null;

            var outputLen = (nuint)output.Length;
            uint flags = compressed ? Secp256K1EcCompressed : Secp256K1EcUncompressed;

            failed = secp256k1_ec_pubkey_serialize(_context, outputPtr, ref outputLen, publicKey, flags) == 0;

            if (failed)
                return null;
        }

        return output.ToArray();
    }

    public static byte[]? SignCompact(ReadOnlySpan<byte> messageHash, ReadOnlySpan<byte> privateKey, out int recoveryId)
    {
        recoveryId = 0;

        if (privateKey.Length == 0)
            return null;

        byte* signature = stackalloc byte[65];

        fixed (byte* messageHashPtr = &MemoryMarshal.GetReference(messageHash))
        fixed (byte* privateKeyPtr = &MemoryMarshal.GetReference(privateKey))
        {
            if (secp256k1_ecdsa_sign_recoverable(_context, signature, messageHashPtr, privateKeyPtr, null, null) == 0)
                return null;

            Span<byte> compactSignature = stackalloc byte[64];

            fixed (byte* compactSignaturePtr = &MemoryMarshal.GetReference(compactSignature))
            {
                if (secp256k1_ecdsa_recoverable_signature_serialize_compact(
                    _context, compactSignaturePtr, out recoveryId, signature) == 0)
                {
                    return null;
                }
            }
            
            return compactSignature.ToArray();
        }
    }

    [SkipLocalsInit]
    public static bool RecoverKeyFromCompact(Span<byte> output, ReadOnlySpan<byte> messageHash, ReadOnlySpan<byte> compactSignature, int recoveryId, bool compressed)
    {
        int expectedLength = compressed ? 33 : 65;

        ArgumentOutOfRangeException.ThrowIfNotEqual(output.Length, expectedLength, nameof(output));

        byte* recoverableSignature = stackalloc byte[65];

        fixed (byte* compactSigPtr = &MemoryMarshal.GetReference(compactSignature))
        {
            if (secp256k1_ecdsa_recoverable_signature_parse_compact(
                _context, recoverableSignature, compactSigPtr, recoveryId) == 0)
            {
                return false;
            }

            Unsafe.SkipInit(out Vector512<byte> publicKey);
            var publicKeyPtr = (byte*)&publicKey;

            fixed (byte* messageHashPtr = &MemoryMarshal.GetReference(messageHash))
            {
                if (secp256k1_ecdsa_recover(_context, publicKeyPtr, recoverableSignature, messageHashPtr) == 0)
                    return false;
            }

            uint flags = compressed ? Secp256K1EcCompressed : Secp256K1EcUncompressed;
            var outputLen = (nuint)output.Length;

            fixed (byte* outputPtr = &MemoryMarshal.GetReference(output))
                return secp256k1_ec_pubkey_serialize(_context, outputPtr, ref outputLen, publicKeyPtr, flags) != 0;
        }
    }

    public static bool Ecdh(Span<byte> output, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(output.Length, 32, nameof(output));
        ArgumentOutOfRangeException.ThrowIfEqual(privateKey.Length, 0, nameof(privateKey));

        delegate* unmanaged[Cdecl]<byte*, byte*, byte*, void*, int> hashfp = &HashFunction;

        fixed (byte* outputPtr = &MemoryMarshal.GetReference(output))
        fixed (byte* publicKeyPtr = &MemoryMarshal.GetReference(publicKey))
        fixed (byte* privateKeyPtr = &MemoryMarshal.GetReference(privateKey))
            return secp256k1_ecdh(_context, outputPtr, publicKeyPtr, privateKeyPtr, hashfp, null) == 1;
    }

    public static byte[] EcdhSerialized(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        Span<byte> serializedKey = stackalloc byte[65];
        ToPublicKeyArray(serializedKey, publicKey);
        Span<byte> key = stackalloc byte[64];
        PublicKeyParse(key, serializedKey);
        Span<byte> result = stackalloc byte[32];
        Ecdh(result, key, privateKey);
        return result.ToArray();
    }

    public static byte[] Decompress(Span<byte> compressed)
    {
        Span<byte> serializedKey = stackalloc byte[65];
        Span<byte> publicKey = stackalloc byte[64];
        PublicKeyParse(publicKey, compressed);

        if (!PublicKeySerialize(serializedKey, publicKey))
        {
            throw new CryptographicException("Failed to serialize public key");
        }

        return serializedKey.ToArray();
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int HashFunction(byte* output, byte* x, byte* y, void* d)
    {
        Unsafe.AsRef<Vector256<byte>>(output) = Vector256.Load(x);

        return 1;
    }

    /// <summary>
    /// Parse a variable-length public key into the pubkey object.
    /// This function supports parsing compressed (33 bytes, header byte 0x02 or
    /// 0x03), uncompressed(65 bytes, header byte 0x04), or hybrid(65 bytes, header
    /// byte 0x06 or 0x07) format public keys.
    /// </summary>
    /// <param name="publicKey">(Output) pointer to a pubkey object. If 1 is returned, it is set to a parsed version of input. If not, its value is undefined.</param>
    /// <param name="serializedPublicKey">Serialized public key.</param>
    /// <returns>True if the public key was fully valid, false if the public key could not be parsed or is invalid.</returns>
    private static bool PublicKeyParse(Span<byte> publicKey, Span<byte> serializedPublicKey)
    {
        var inputLen = serializedPublicKey.Length;

        if (inputLen != 33 && inputLen != 65)
            throw new ArgumentException($"{nameof(serializedPublicKey)} must be 33 or 65 bytes");

        ArgumentOutOfRangeException.ThrowIfLessThan(publicKey.Length, 64, nameof(publicKey));

        fixed (byte* publicKeyPtr = &MemoryMarshal.GetReference(publicKey))
        fixed (byte* serializedPtr = &MemoryMarshal.GetReference(serializedPublicKey))
            return secp256k1_ec_pubkey_parse(_context, publicKeyPtr, serializedPtr, (nuint)inputLen) == 1;
    }

    /// <summary>
    /// Serialize a pubkey object into a serialized byte sequence.
    /// </summary>
    /// <param name="serializedPublicKeyOutput">65-byte (if compressed==0) or 33-byte (if compressed==1) output to place the serialized key in.</param>
    /// <param name="publicKey">The secp256k1_pubkey initialized public key.</param>
    /// <param name="flags">SECP256K1_EC_COMPRESSED if serialization should be in compressed format, otherwise SECP256K1_EC_UNCOMPRESSED.</param>
    private static bool PublicKeySerialize(ReadOnlySpan<byte> serializedPublicKeyOutput, Span<byte> publicKey, uint flags = Secp256K1EcUncompressed)
    {
        bool compressed = (flags & Secp256K1EcCompressed) == Secp256K1EcCompressed;
        int serializedPubKeyLength = compressed ? 33 : 65;

        if (serializedPublicKeyOutput.Length < serializedPubKeyLength)
        {
            string compressedStr = compressed ? "compressed" : "uncompressed";
            throw new ArgumentException($"{nameof(serializedPublicKeyOutput)} ({compressedStr}) must be {serializedPubKeyLength} bytes");
        }

        int expectedInputLength = flags == Secp256K1EcCompressed ? 33 : 64;

        if (publicKey.Length != expectedInputLength)
            throw new ArgumentException($"{nameof(publicKey)} must be {expectedInputLength} bytes");

        var newLength = (nuint)serializedPubKeyLength;

        fixed (byte* serializedPtr = &MemoryMarshal.GetReference(serializedPublicKeyOutput))
        fixed (byte* pubKeyPtr = &MemoryMarshal.GetReference(publicKey))
        {
            bool success = secp256k1_ec_pubkey_serialize(
                _context, serializedPtr, ref newLength, pubKeyPtr, flags) == 1;

            return success && newLength == (nuint)serializedPubKeyLength;
        }
    }

    private static void ToPublicKeyArray(ReadOnlySpan<byte> serializedKey, ReadOnlySpan<byte> unmanaged)
    {
        // Define the public key array
        Span<byte> publicKey = stackalloc byte[64];

        // Add our uncompressed prefix to our key.
        Span<byte> uncompressedPrefixedPublicKey = stackalloc byte[65];
        uncompressedPrefixedPublicKey[0] = 4;
        unmanaged.CopyTo(uncompressedPrefixedPublicKey[1..]);

        // Parse our public key from the serialized data.
        if (!PublicKeyParse(publicKey, uncompressedPrefixedPublicKey))
            throw new CryptographicException("Failed parsing public key");

        // Serialize the public key
        if (!PublicKeySerialize(serializedKey, publicKey, Secp256K1EcUncompressed))
            throw new CryptographicException("Failed serializing public key");
    }

    private static nint OnResolvingUnmanagedDll(Assembly context, string name)
    {
        if (context != typeof(SecP256k1).Assembly || !LibraryName.Equals(name, StringComparison.Ordinal))
            return nint.Zero;

        string platform;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            name = $"lib{name}.so";
            platform = "linux";
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            name = $"lib{name}.dylib";
            platform = "osx";
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            name = $"{name}.dll";
            platform = "win";
        }
        else
            throw new PlatformNotSupportedException();

        var arch = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();

        return NativeLibrary.Load($"runtimes/{platform}-{arch}/native/{name}", context, DllImportSearchPath.AssemblyDirectory);
    }
}
