# Contributing to open-mpc-vault

Contributions to `open-mpc-vault` are welcome. Because this repository implements cryptographic primitives and key management infrastructure, all contributions are subject to rigorous review and strict engineering standards.

## Principles

1. **Cryptographic Integrity**: Never introduce custom or untested cryptographic algorithms. Rely strictly on audited primitives, standard RFCs, and BIP specifications.
2. **Defensive Memory Handling**: Any function that handles sensitive material (seeds, private keys, raw shards, passphrases) must guarantee buffer zeroization (`Buffer.fill(0)`) in `finally` blocks.
3. **No External Telemetry or Network Calls**: The core library (`src/crypto/`) must remain entirely self-contained with no network dependencies.
4. **Strict Typing**: All TypeScript code must compile with `noImplicitAny`, `strictNullChecks`, and zero compiler warnings.

## Development Workflow

### 1. Environment Setup

```bash
git clone https://github.com/devstanl3y/open-mpc-vault.git
cd open-mpc-vault
npm install
```

### 2. Branching Model

- Create focused feature or bugfix branches off `main`:
  - `feat/<feature-name>`
  - `fix/<bug-name>`
  - `refactor/<scope>`
- Keep commits granular and follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
  - `feat(crypto): add scrypt key stretching option`
  - `fix(shamir): validate polynomial degree input bounds`
  - `test(hdwallet): add test vectors for bip84 testnet`

### 3. Verification

Before opening a pull request, verify that the test suite and TypeScript compiler pass cleanly:

```bash
npm run build
npm test
```

All new features and bug fixes must include unit tests located under `tests/`.

## Pull Request Guidelines

1. **Description**: Clearly explain the rationale, mathematical basis, or bug being addressed.
2. **Security Considerations**: Explicitly document any impact on the threat model, memory management, or side-channel resistance.
3. **Scope**: Keep pull requests focused on a single concern. Avoid combining refactoring with algorithmic modifications.
4. **Review**: At least one maintainer review is required prior to merging.

## Security Vulnerabilities

Do **not** report security vulnerabilities through public GitHub issues. Follow the instructions in [SECURITY.md](SECURITY.md) for responsible disclosure.
