// SPDX-FileCopyrightText: 2024 Demerzel Solutions Limited
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

    static unsafe SecP256k1()
    {
        SetLibraryFallbackResolver();

        Context = CreateContext();

        Span<byte> seed = stackalloc byte[32];

        RandomNumberGenerator.Fill(seed);

        fixed (byte* ptr = seed)
        {
            var result = secp256k1_context_randomize(Context, ptr);

            Debug.Assert(result == 1, "Context randomization failed");
        }
    }

#pragma warning disable CA1401 // P/Invokes should not be visible
    [LibraryImport(LibraryName)]
    public static partial IntPtr secp256k1_context_create(uint flags);

    [LibraryImport(LibraryName)]
    public static partial IntPtr secp256k1_context_destroy(IntPtr context);

    [LibraryImport(LibraryName)]
    public static partial int secp256k1_ec_seckey_verify(IntPtr context, [Out] byte[] seckey);

    [LibraryImport(LibraryName)]
    public static unsafe partial int secp256k1_ec_pubkey_create(IntPtr context, void* pubkey, [In] byte[] seckey);

    [LibraryImport(LibraryName)]
    public static unsafe partial int secp256k1_ec_pubkey_serialize(IntPtr context, void* serializedPublicKey, ref nint outputSize, void* publicKey, uint flags);

    [LibraryImport(LibraryName)]
    public static partial int secp256k1_ecdsa_sign_recoverable(IntPtr context, [Out] byte[] signature, [In] byte[] messageHash, [In] byte[] privateKey, IntPtr nonceFunction, IntPtr nonceData);

    [LibraryImport(LibraryName)]
    public static partial int secp256k1_ecdsa_recoverable_signature_serialize_compact(IntPtr context, [Out] byte[] compactSignature, out int recoveryId, [In] byte[] signature);

    [LibraryImport(LibraryName)]
    public static unsafe partial int secp256k1_ecdsa_recoverable_signature_parse_compact(IntPtr context, void* signature, void* compactSignature, int recoveryId);

    [LibraryImport(LibraryName)]
    public static unsafe partial int secp256k1_ecdsa_recover(IntPtr context, void* publicKey, void* signature, [Out] byte[] message);

    [LibraryImport(LibraryName)]
    public static partial int secp256k1_ecdh(IntPtr context, [Out] byte[] output, [In] byte[] publicKey, [In] byte[] privateKey, IntPtr hashFunctionPointer, IntPtr data);

    [LibraryImport(LibraryName)]
    public static unsafe partial int secp256k1_ec_pubkey_parse(IntPtr ctx, void* pubkey, void* input, nint inputlen);

    [LibraryImport(LibraryName)]
    public static unsafe partial int secp256k1_context_randomize(nint ctx, void* seed32);
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

    public static bool VerifyPrivateKey(byte[] privateKey)
    {
        return secp256k1_ec_seckey_verify(Context, privateKey) == 1;
    }

    public static unsafe byte[]? GetPublicKey(byte[] privateKey, bool compressed)
    {
        Span<byte> publicKey = stackalloc byte[64];
        Span<byte> serializedPublicKey = stackalloc byte[compressed ? 33 : 65];

        fixed (byte* serializedPtr = &MemoryMarshal.GetReference(serializedPublicKey), pubKeyPtr = &MemoryMarshal.GetReference(publicKey))
        {
            bool keyDerivationFailed = secp256k1_ec_pubkey_create(Context, pubKeyPtr, privateKey) == 0;

            if (keyDerivationFailed)
            {
                return null;
            }

            nint outputSize = serializedPublicKey.Length;
            uint flags = compressed ? Secp256K1EcCompressed : Secp256K1EcUncompressed;

            bool serializationFailed = secp256k1_ec_pubkey_serialize(Context, serializedPtr, ref outputSize, pubKeyPtr, flags) == 0;

            if (serializationFailed)
            {
                return null;
            }
        }

        return serializedPublicKey.ToArray();
    }

    public static byte[]? SignCompact(byte[] messageHash, byte[] privateKey, out int recoveryId)
    {
        byte[] recoverableSignature = new byte[65];
        recoveryId = 0;

        if (secp256k1_ecdsa_sign_recoverable(
            Context, recoverableSignature, messageHash, privateKey, IntPtr.Zero, IntPtr.Zero) == 0)
        {
            return null;
        }

        byte[] compactSignature = new byte[64];

        if (secp256k1_ecdsa_recoverable_signature_serialize_compact(
            Context, compactSignature, out recoveryId, recoverableSignature) == 0)
        {
            return null;
        }

        return compactSignature;
    }

    [SkipLocalsInit]
    public static unsafe bool RecoverKeyFromCompact(Span<byte> output, byte[] messageHash, ReadOnlySpan<byte> compactSignature, int recoveryId, bool compressed)
    {
        int expectedLength = compressed ? 33 : 65;

        ArgumentOutOfRangeException.ThrowIfNotEqual(output.Length, expectedLength);

        fixed (byte*
            compactSigPtr = &MemoryMarshal.GetReference(compactSignature),
            serializedPublicKeyPtr = &MemoryMarshal.GetReference(output))
        {
            Span<byte> recoverableSignature = stackalloc byte[65];
            Unsafe.SkipInit(out Vector512<byte> publicKey);

            // Stack is fixed, so we don't need to use fixed expression for this pointer
            void* recoverableSignaturePtr = Unsafe.AsPointer(ref MemoryMarshal.GetReference(recoverableSignature));

            if (secp256k1_ecdsa_recoverable_signature_parse_compact(
                Context, recoverableSignaturePtr, compactSigPtr, recoveryId) == 0)
            {
                return false;
            }

            if (secp256k1_ecdsa_recover(Context, &publicKey, recoverableSignaturePtr, messageHash) == 0)
            {
                return false;
            }

            uint flags = compressed ? Secp256K1EcCompressed : Secp256K1EcUncompressed;
            nint outputSize = output.Length;

            if (secp256k1_ec_pubkey_serialize(
                Context, serializedPublicKeyPtr, ref outputSize, &publicKey, flags) == 0)
            {
                return false;
            }

            return true;
        }
    }

    unsafe delegate int secp256k1_ecdh_hash_function(void* output, void* x, void* y, IntPtr data);

    private const int OutputSize = 32;

    private readonly static secp256k1_ecdh_hash_function _hashFunction = static (void* output, void* x, void* y, IntPtr d) =>
    {
        Unsafe.AsRef<Vector256<byte>>(output) = Vector256.Load((byte*)x);
        return 1;
    };

    private readonly static IntPtr _hashFunctionPtr = Marshal.GetFunctionPointerForDelegate(_hashFunction);

    public static unsafe bool Ecdh(byte[] agreement, byte[] publicKey, byte[] privateKey)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(agreement.Length, OutputSize);
        return secp256k1_ecdh(Context, agreement, publicKey, privateKey, _hashFunctionPtr, IntPtr.Zero) == 1;
    }

    public static byte[] EcdhSerialized(byte[] publicKey, byte[] privateKey)
    {
        Span<byte> serializedKey = stackalloc byte[65];
        ToPublicKeyArray(serializedKey, publicKey);
        byte[] key = new byte[64];
        PublicKeyParse(key, serializedKey);
        byte[] result = new byte[32];
        Ecdh(result, key, privateKey);
        return result;
    }

    public static byte[] Decompress(Span<byte> compressed)
    {
        Span<byte> serializedKey = stackalloc byte[65];
        byte[] publicKey = new byte[64];
        PublicKeyParse(publicKey, compressed);

        if (!PublicKeySerialize(serializedKey, publicKey))
        {
            throw new CryptographicException("Failed to serialize public key");
        }

        return serializedKey.ToArray();
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
    private static unsafe bool PublicKeyParse(Span<byte> publicKeyOutput, Span<byte> serializedPublicKey)
    {
        nint inputLen = serializedPublicKey.Length;
        if (inputLen != 33 && inputLen != 65)
        {
            throw new ArgumentException($"{nameof(serializedPublicKey)} must be 33 or 65 bytes");
        }

        if (publicKeyOutput.Length < 64)
        {
            throw new ArgumentException($"{nameof(publicKeyOutput)} must be {64} bytes");
        }

        fixed (byte* pubKeyPtr = &MemoryMarshal.GetReference(publicKeyOutput), serializedPtr = &MemoryMarshal.GetReference(serializedPublicKey))
        {
            return secp256k1_ec_pubkey_parse(
                Context, pubKeyPtr, serializedPtr, inputLen) == 1;
        }
    }

    /// <summary>
    /// Serialize a pubkey object into a serialized byte sequence.
    /// </summary>
    /// <param name="serializedPublicKeyOutput">65-byte (if compressed==0) or 33-byte (if compressed==1) output to place the serialized key in.</param>
    /// <param name="publicKey">The secp256k1_pubkey initialized public key.</param>
    /// <param name="flags">SECP256K1_EC_COMPRESSED if serialization should be in compressed format, otherwise SECP256K1_EC_UNCOMPRESSED.</param>
    private static unsafe bool PublicKeySerialize(Span<byte> serializedPublicKeyOutput, Span<byte> publicKey, uint flags = Secp256K1EcUncompressed)
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

        nint newLength = serializedPubKeyLength;

        fixed (byte* serializedPtr = &MemoryMarshal.GetReference(serializedPublicKeyOutput), pubKeyPtr = &MemoryMarshal.GetReference(publicKey))
        {
            bool success = secp256k1_ec_pubkey_serialize(
                Context, serializedPtr, ref newLength, pubKeyPtr, flags) == 1;

            return success && newLength == serializedPubKeyLength;
        }
    }

    private static void ToPublicKeyArray(Span<byte> serializedKey, byte[] unmanaged)
    {
        // Define the public key array
        Span<byte> publicKey = stackalloc byte[64];

        // Add our uncompressed prefix to our key.
        Span<byte> uncompressedPrefixedPublicKey = stackalloc byte[65];
        uncompressedPrefixedPublicKey[0] = 4;
        unmanaged.AsSpan().CopyTo(uncompressedPrefixedPublicKey[1..]);

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
        Assembly assembly = typeof(SecP256k1).Assembly;

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
            {
                throw new PlatformNotSupportedException();
            }

            var arch = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();

            return NativeLibrary.Load($"runtimes/{platform}-{arch}/native/{name}", context, DllImportSearchPath.AssemblyDirectory);
        };
    }
}
