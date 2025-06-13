// SPDX-FileCopyrightText: 2025 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;

namespace Nethermind.Crypto;

public static unsafe partial class SecP256k1
{
    [LibraryImport(LibraryName)]
    private static partial nint secp256k1_context_create(uint flags);

    [LibraryImport(LibraryName)]
    private static partial nint secp256k1_context_destroy(nint ctx);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ec_seckey_verify(nint ctx, byte* seckey);

    [LibraryImport(LibraryName)]
    private static unsafe partial int secp256k1_ec_pubkey_create(nint ctx, byte* pubkey, byte* seckey);

    [LibraryImport(LibraryName)]
    private static unsafe partial int secp256k1_ec_pubkey_serialize(nint ctx, byte* output, ref nuint outputlen, void* publicKey, uint flags);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ecdsa_sign_recoverable(nint ctx, byte* sig, byte* msghash32, byte* seckey, delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, void*, uint, int> noncefp, void* ndata);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ecdsa_recoverable_signature_serialize_compact(nint ctx, byte* output64, out int recid, byte* sig);

    [LibraryImport(LibraryName)]
    private static unsafe partial int secp256k1_ecdsa_recoverable_signature_parse_compact(nint ctx, byte* sig, byte* input64, int recid);

    [LibraryImport(LibraryName)]
    private static unsafe partial int secp256k1_ecdsa_recover(nint ctx, byte* pubkey, byte* sig, byte* msghash32);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ecdh(nint ctx, byte* output, byte* pubkey, byte* seckey, delegate* unmanaged[Cdecl]<byte*, byte*, byte*, void*, int> hashfp, void* data);

    [LibraryImport(LibraryName)]
    private static unsafe partial int secp256k1_ec_pubkey_parse(nint ctx, void* pubkey, void* input, nint inputlen);

    [LibraryImport(LibraryName)]
    private static unsafe partial int secp256k1_context_randomize(nint ctx, byte* seed32);
}
