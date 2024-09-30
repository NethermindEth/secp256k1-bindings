// SPDX-FileCopyrightText: 2023 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Security.Cryptography;

namespace Nethermind.Crypto;

public static partial class SecP256k1
{
    private const string LibraryName = "secp256k1";

    static SecP256k1()
    {
        SetLibraryFallbackResolver();

        Context = CreateContext();

        Span<byte> seed = stackalloc byte[32];

        RandomNumberGenerator.Fill(seed);

        var result = secp256k1_context_randomize(Context, seed);
        Debug.Assert(result == 1, "Context randomization failed");
    }

#pragma warning disable CA1401 // P/Invokes should not be visible
    [LibraryImport(LibraryName)]
    public static partial IntPtr secp256k1_context_create(uint flags);

    [LibraryImport(LibraryName)]
    public static partial IntPtr secp256k1_context_destroy(IntPtr context);

    [LibraryImport(LibraryName)]
    public static partial int secp256k1_ec_seckey_verify(IntPtr context, ReadOnlySpan<byte> seckey);

    [LibraryImport(LibraryName)]
    public static partial int secp256k1_ec_pubkey_create(IntPtr context, Span<byte> pubkey, ReadOnlySpan<byte> seckey);

    [LibraryImport(LibraryName)]
    public static partial int secp256k1_ec_pubkey_serialize(IntPtr context, Span<byte> serializedPublicKey, ref uint outputSize, ReadOnlySpan<byte> publicKey, uint flags);

    [LibraryImport(LibraryName)]
    public static partial int secp256k1_ecdsa_sign_recoverable(IntPtr context, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> messageHash, ReadOnlySpan<byte> privateKey, IntPtr nonceFunction, IntPtr nonceData);

    [LibraryImport(LibraryName)]
    public static partial int secp256k1_ecdsa_recoverable_signature_serialize_compact(IntPtr context, ReadOnlySpan<byte> compactSignature, out int recoveryId, ReadOnlySpan<byte> signature);

    [LibraryImport(LibraryName)]
    public static partial int secp256k1_ecdsa_recoverable_signature_parse_compact(IntPtr context, Span<byte> signature, Span<byte> compactSignature, int recoveryId);

    [LibraryImport(LibraryName)]
    public static partial int secp256k1_ecdsa_recover(IntPtr context, Span<byte> publicKey, Span<byte> signature, ReadOnlySpan<byte> message);

    [LibraryImport(LibraryName)]
    public static partial int secp256k1_ecdh(IntPtr context, ReadOnlySpan<byte> output, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey, IntPtr hashFunctionPointer, IntPtr data);

    [LibraryImport(LibraryName)]
    public static partial int secp256k1_ec_pubkey_parse(IntPtr ctx, Span<byte> pubkey, ReadOnlySpan<byte> input, uint inputlen);

    [LibraryImport(LibraryName)]
    public static partial int secp256k1_context_randomize(nint ctx, Span<byte> seed32);
#pragma warning restore CA1401 // P/Invokes should not be visible

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

    private static readonly IntPtr Context;

    private static IntPtr CreateContext()
    {
        return secp256k1_context_create(Secp256K1ContextSign | Secp256K1ContextVerify);
    }

    public static bool VerifyPrivateKey(ReadOnlySpan<byte> privateKey)
    {
        return secp256k1_ec_seckey_verify(Context, privateKey) == 1;
    }

    public static bool GetPublicKey(ReadOnlySpan<byte> privateKey, bool compressed, Span<byte> serializedPublicKey)
    {
        Span<byte> publicKey = stackalloc byte[64];

        bool keyDerivationFailed = secp256k1_ec_pubkey_create(Context, publicKey, privateKey) == 0;

        if (keyDerivationFailed)
        {
            return false;
        }

        uint outputSize = (uint)serializedPublicKey.Length;
        uint flags = compressed ? Secp256K1EcCompressed : Secp256K1EcUncompressed;

        bool serializationFailed = secp256k1_ec_pubkey_serialize(Context, serializedPublicKey, ref outputSize, publicKey, flags) == 0;

        if (serializationFailed)
        {
            return false;
        }

        return true;
    }

    public static byte[]? GetPublicKey(ReadOnlySpan<byte> privateKey, bool compressed) // Compatable with old API
    {
        byte[] buffer = new byte[compressed ? 33 : 65];

        if (GetPublicKey(privateKey, compressed, buffer))
        {
            return buffer;
        }

        return null;
    }

    public static bool SignCompact(ReadOnlySpan<byte> messageHash, ReadOnlySpan<byte> privateKey, Span<byte> compactSignature, out int recoveryId)
    {
        if (compactSignature.Length != 64)
        {
            throw new ArgumentException($"{nameof(compactSignature)} length should be 64");
        }

        Span<byte> recoverableSignature = stackalloc byte[65];
        recoveryId = 0;

        if (secp256k1_ecdsa_sign_recoverable(
            Context, recoverableSignature, messageHash, privateKey, IntPtr.Zero, IntPtr.Zero) == 0)
        {
            return false;
        }

        if (secp256k1_ecdsa_recoverable_signature_serialize_compact(
            Context, compactSignature, out recoveryId, recoverableSignature) == 0)
        {
            return false;
        }

        return true;
    }

    public static byte[]? SignCompact(ReadOnlySpan<byte> messageHash, ReadOnlySpan<byte> privateKey, out int recoveryId) // Compatable with old API
    {
        byte[] buffer = new byte[64];
        recoveryId = 0;

        if (SignCompact(messageHash, privateKey, buffer, out recoveryId))
        {
            return buffer;
        }

        return null;
    }

    // public static unsafe bool RecoverKeyFromCompact(Span<byte> output, byte[] messageHash, Span<byte> recoverableSignature, bool compressed)
    // {
    //     Span<byte> publicKey = stackalloc byte[64];
    //     int expectedLength = compressed ? 33 : 65;
    //     if (output.Length != expectedLength)
    //     {
    //         throw new ArgumentException($"{nameof(output)} length should be {expectedLength}");
    //     }
    //
    //     fixed (byte*
    //         pubKeyPtr = &MemoryMarshal.GetReference(publicKey),
    //         recoverableSignaturePtr = &MemoryMarshal.GetReference(recoverableSignature),
    //         serializedPublicKeyPtr = &MemoryMarshal.GetReference(output))
    //     {
    //         if (!secp256k1_ecdsa_recover(Context, pubKeyPtr, recoverableSignaturePtr, messageHash))
    //         {
    //             return false;
    //         }
    //         
    //         uint flags = compressed ? Secp256K1EcCompressed : Secp256K1EcUncompressed;
    //         
    //         uint outputSize = (uint) output.Length;
    //         if (!secp256k1_ec_pubkey_serialize(
    //             Context, serializedPublicKeyPtr, ref outputSize, pubKeyPtr, flags))
    //         {
    //             return false;
    //         }
    //
    //         return true;
    //     }
    // }

    public static bool RecoverKeyFromCompact(Span<byte> output, ReadOnlySpan<byte> messageHash, Span<byte> compactSignature, int recoveryId, bool compressed)
    {
        Span<byte> recoverableSignature = stackalloc byte[65];
        Span<byte> publicKey = stackalloc byte[64];
        int expectedLength = compressed ? 33 : 65;
        if (output.Length != expectedLength)
        {
            throw new ArgumentException($"{nameof(output)} length should be {expectedLength}");
        }
       
        if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            Context, recoverableSignature, compactSignature, recoveryId) == 0)
        {
            return false;
        }

        if (secp256k1_ecdsa_recover(Context, publicKey, recoverableSignature, messageHash) == 0)
        {
            return false;
        }

        uint flags = compressed ? Secp256K1EcCompressed : Secp256K1EcUncompressed;
        uint outputSize = (uint)output.Length;

        if (secp256k1_ec_pubkey_serialize(
            Context, output, ref outputSize, publicKey, flags) == 0)
        {
            return false;
        }

        return true;
    }

    unsafe delegate int secp256k1_ecdh_hash_function(void* output, void* x, void* y, IntPtr data);

    public static unsafe bool Ecdh(ReadOnlySpan<byte> agreement, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        int outputLength = agreement.Length;

        // TODO: should probably do that only once
        secp256k1_ecdh_hash_function hashFunctionPtr = (void* output, void* x, void* y, IntPtr d) =>
        {
            Span<byte> outputSpan = new(output, outputLength);
            Span<byte> xSpan = new(x, 32);
            if (xSpan.Length < 32)
            {
                return 0;
            }

            xSpan.CopyTo(outputSpan);
            return 1;
        };

        GCHandle gch = GCHandle.Alloc(hashFunctionPtr);
        try
        {
            IntPtr fp = Marshal.GetFunctionPointerForDelegate(hashFunctionPtr);
            {
                return secp256k1_ecdh(Context, agreement, publicKey, privateKey, fp, IntPtr.Zero) == 1;
            }
        }
        finally
        {
            gch.Free();
        }
    }

    public static byte[] EcdhSerialized(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        Span<byte> serializedKey = stackalloc byte[65];

        ToPublicKeyArray(serializedKey, publicKey);
        byte[] key = new byte[64];
        PublicKeyParse(key, serializedKey);

        byte[] result = new byte[32];
        Ecdh(result, key, privateKey);
        return result;
    }

    public static bool Decompress(ReadOnlySpan<byte> compressed, Span<byte> serializedKey)
    {
        Span<byte> publicKey = stackalloc byte[64];
        PublicKeyParse(publicKey, compressed);

        return PublicKeySerialize(serializedKey, publicKey);
    }

    public static byte[]? Decompress(ReadOnlySpan<byte> compressed) // Compatable with old API
    {
        byte[] buffer = new byte[65];
        if (Decompress(compressed, buffer))
        {
            return buffer;
        }

        return null;
    }

    /// <summary>
    /// Parse a variable-length public key into the pubkey object.
    /// This function supports parsing compressed (33 bytes, header byte 0x02 or
    /// 0x03), uncompressed(65 bytes, header byte 0x04), or hybrid(65 bytes, header
    /// byte 0x06 or 0x07) format public keys.
    /// </summary>
    /// <param name="publicKeyOutput">(Output) pointer to a pubkey object. If 1 is returned, it is set to a parsed version of input. If not, its value is undefined.</param>
    /// <param name="serializedPublicKey">Serialized public key.</param>
    /// <returns>True if the public key was fully valid, false if the public key could not be parsed or is invalid.</returns>
    private static bool PublicKeyParse(Span<byte> publicKeyOutput, ReadOnlySpan<byte> serializedPublicKey)
    {
        int inputLen = serializedPublicKey.Length;
        if (inputLen != 33 && inputLen != 65)
        {
            throw new ArgumentException($"{nameof(serializedPublicKey)} must be 33 or 65 bytes");
        }

        if (publicKeyOutput.Length < 64)
        {
            throw new ArgumentException($"{nameof(publicKeyOutput)} must be {64} bytes");
        }

        return secp256k1_ec_pubkey_parse(Context, publicKeyOutput, serializedPublicKey, (uint)inputLen) == 1;
    }

    /// <summary>
    /// Serialize a pubkey object into a serialized byte sequence.
    /// </summary>
    /// <param name="serializedPublicKeyOutput">65-byte (if compressed==0) or 33-byte (if compressed==1) output to place the serialized key in.</param>
    /// <param name="publicKey">The secp256k1_pubkey initialized public key.</param>
    /// <param name="flags">SECP256K1_EC_COMPRESSED if serialization should be in compressed format, otherwise SECP256K1_EC_UNCOMPRESSED.</param>
    private static bool PublicKeySerialize(Span<byte> serializedPublicKeyOutput, ReadOnlySpan<byte> publicKey, uint flags = Secp256K1EcUncompressed)
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
        {
            throw new ArgumentException($"{nameof(publicKey)} must be {expectedInputLength} bytes");
        }

        uint newLength = (uint)serializedPubKeyLength;

        bool success = secp256k1_ec_pubkey_serialize(Context, serializedPublicKeyOutput, ref newLength, publicKey, flags) == 1;
        return success && newLength == serializedPubKeyLength;
    }

    private static void ToPublicKeyArray(Span<byte> serializedKey, ReadOnlySpan<byte> unmanaged)
    {
        // Define the public key array
        Span<byte> publicKey = stackalloc byte[64];

        // Add our uncompressed prefix to our key.
        Span<byte> uncompressedPrefixedPublicKey = stackalloc byte[65];
        uncompressedPrefixedPublicKey[0] = 4;
        unmanaged.CopyTo(uncompressedPrefixedPublicKey[1..]);

        // Parse our public key from the serialized data.
        if (!PublicKeyParse(publicKey, uncompressedPrefixedPublicKey))
        {
            throw new CryptographicException("Failed parsing public key");
        }

        // Serialize the public key
        if (!PublicKeySerialize(serializedKey, publicKey, Secp256K1EcUncompressed))
        {
            throw new CryptographicException("Failed serializing public key");
        }
    }

    private static void SetLibraryFallbackResolver()
    {
        var assembly = typeof(SecP256k1).Assembly;

        AssemblyLoadContext.GetLoadContext(assembly)!.ResolvingUnmanagedDll += (Assembly context, string name) =>
        {
            if (context != assembly || !LibraryName.Equals(name, StringComparison.Ordinal))
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

            return NativeLibrary.Load($"runtimes/{platform}-{arch}/native/{name}", context, LibraryImportSearchPath.AssemblyDirectory);
        };
    }
}
