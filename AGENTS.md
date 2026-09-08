# AGENTS instructions

C# bindings for the Bitcoin Core libsecp256k1 library. See [global.json](./global.json) and [src](./src/) directory for the project requirements and configuration.

## Project structure

- [src](./src/): The main codebase.
- [build-secp256k1.yml](./.github/workflows/build-secp256k1.yml): Builds libsecp256k1 for the specified version.
- [test-publish.yml](./.github/workflows/test-publish.yml): Runs the tests and optionally publishes on NuGet.

## Coding guidelines

- Follow [.editorconfig](./.editorconfig).
- Do not assume; measure, research, ask if unsure.
- Keep comments short and to the point.
- Add tests for new code and bug fixes.
- Use conventional commits; keep scoped and imperative.
- Do not edit the prebuilt binaries under `src/Nethermind.Crypto.SecP256k1/runtimes` (Git LFS); update them by running [build-secp256k1.yml](./.github/workflows/build-secp256k1.yml).
- Prefer the latest versions of GitHub Actions and runners.
- Update [THIRD-PARTY-NOTICES](./THIRD-PARTY-NOTICES) when introducing a dependency if needed.
- Keep [AGENTS.md](./AGENTS.md) in sync with the ongoing development.
