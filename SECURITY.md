# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1.0 | No |

## Reporting a Vulnerability

The maintainers of `open-mpc-vault` take the security of cryptographic software seriously. If you discover a vulnerability or potential weakness, please disclose it responsibly.

### Disclosure Process

1. **Do not open a public issue.**
2. Send an advisory email to: **stanleyjinadu@gmail.com** with the subject line: `[SECURITY] open-mpc-vault: <Brief Summary>`.
3. If necessary, request a PGP key for encrypted communication.
4. Include the following details in your report:
   - Type of vulnerability (e.g. side-channel timing, memory leakage, polynomial interpolation edge case, cryptographic misuse).
   - Affected components, files, or line numbers.
   - Step-by-step reproduction instructions or a minimal proof of concept.
   - Potential impact on key integrity or threshold guarantees.

### Response Timeline

- **Initial Acknowledgement**: Within 48 hours of receipt.
- **Triage and Assessment**: Within 5 business days.
- **Remediation and Advisory**: A patched release will be coordinated with the reporter before public disclosure.

## Security Architecture Principles

- **Zero Single-Point-of-Failure**: Possession of a single shard must yield zero information regarding the underlying secret under the standard discrete logarithm and Shamir information-theoretic assumptions.
- **Explicit Memory Zeroization**: Consumers of this library are responsible for wiping decrypted buffers in application runtime memory using `buffer.fill(0)`.
- **Authenticated Ciphertexts**: Ciphertexts produced by this library are authenticated via AES-256-GCM tags. Never bypass or discard tag validation.
