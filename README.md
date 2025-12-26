# AuthSystem

A zero-dependency, framework-agnostic authentication system built entirely with native Web Crypto API.

## Features

- 🔐 **RS256 JWT Signing** — Asymmetric keys for microservice compatibility
- 🛡️ **Token Fingerprinting** — OWASP-recommended theft prevention
- 🔑 **PBKDF2 Password Hashing** — 600,000 iterations (OWASP 2023)
- 📱 **Multi-Device Sessions** — Track, list, and revoke sessions per device
- 🔄 **Automatic Key Rotation** — 90-day lifecycle with graceful transitions
- 🌐 **Cross-Runtime** — Node.js, Deno, Bun, Cloudflare Workers, browsers

## Why Zero Dependencies?

| Benefit | Description |
|---------|-------------|
| Security | No supply chain vulnerabilities |
| Portability | Works everywhere Web Crypto API exists |
| Auditability | Complete control over all crypto operations |
| Longevity | No breaking changes from dependency updates |

## Quick Start

```typescript
import { AuthService } from '@authsystem/core';

const auth = new AuthService({
  jwt: {
    issuer: 'https://auth.example.com',
    audience: 'https://api.example.com'
  },
  keys: {
    directory: './keys'
  }
});

// Initialize (generates RSA key pair if none exists)
await auth.initialize();

// Register user
const user = await auth.register('user@example.com', 'securePassword123');

// Login
const { accessToken, cookies } = await auth.login(
  'user@example.com',
  'securePassword123',
  { userAgent: 'Mozilla/5.0...', ip: '192.168.1.1' }
);

// Verify request
const result = await auth.verifyRequest(
  'Bearer ' + accessToken,
  '__Secure-Fpt=...'
);

if (result.valid) {
  console.log('Authenticated user:', result.userId);
}
```

## Token Strategy

```
┌─────────────────┬──────────────────┬─────────────┐
│ Token           │ Storage          │ Lifetime    │
├─────────────────┼──────────────────┼─────────────┤
│ Access Token    │ Client memory    │ 15 minutes  │
│ Refresh Token   │ HttpOnly cookie  │ 30 days     │
│ Fingerprint     │ HttpOnly cookie  │ Session     │
└─────────────────┴──────────────────┴─────────────┘
```

- **Access tokens** returned in response body, stored in client memory (XSS safe)
- **Refresh tokens** stored in `__Secure-Ref` HttpOnly cookie (not accessible to JS)
- **Fingerprint** binds tokens to the browser session, preventing theft

## Project Structure

```
src/
├── crypto/          # Cryptographic primitives (base64url, hash, random)
├── keys/            # RSA key management and rotation
├── jwt/             # Token signing and verification
├── fingerprint/     # Token binding via cookies
├── cookies/         # Cookie serialization and parsing
├── password/        # PBKDF2 hashing
├── session/         # Multi-device session management
├── storage/         # Storage abstractions (memory, filesystem)
└── auth/            # Main AuthService orchestrator

keys/                # Runtime key storage (gitignored)
├── current/         # Active signing keys
└── rotated/         # Keys in grace period
```

## Security Highlights

- **Constant-time comparison** for all secret operations
- **PKCS#8 / SPKI** key formats for interoperability
- **Key ID (`kid`)** in JWT headers for rotation support
- **JWKS endpoint** for public key distribution
- **PHC string format** for password hash storage
- **`__Secure-` cookie prefix** enforcement

## Documentation

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for:

- Detailed architecture diagrams
- Security model explanation
- Token flow sequences
- API reference
- Integration examples (Express, Fastify, client-side)
- Configuration options

## Runtime Compatibility

| Runtime | Version | Status |
|---------|---------|--------|
| Node.js | 18+ | ✅ Full support |
| Node.js | 16-17 | ✅ Via `crypto.webcrypto` |
| Deno | 1.0+ | ✅ Full support |
| Bun | 1.0+ | ✅ Full support |
| Cloudflare Workers | - | ✅ Full support |
| Modern Browsers | - | ✅ Full support |

## License

MIT
