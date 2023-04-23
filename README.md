# secp256k1-bindings

[![Test](https://github.com/nethermindeth/secp256k1-bindings/actions/workflows/test.yml/badge.svg)](https://github.com/nethermindeth/secp256k1-bindings/actions/workflows/test.yml)
[![Nethermind.Numerics.Int256](https://img.shields.io/nuget/v/Nethermind.Crypto.SecP256k1)](https://www.nuget.org/packages/Nethermind.Crypto.SecP256k1)

C# bindings for the Bitcoin Core [libsecp256k1](https://github.com/bitcoin-core/secp256k1) library.

### Build

Files in the `src/Nethermind.Crypto.SecP256k1/runtimes` directory are empty.
Before building the project, these files should be replaced with the respective libsecp256k1 binaries.
