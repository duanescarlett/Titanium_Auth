# AuthSystem Architecture

A zero-dependency, framework-agnostic authentication system built entirely with native Web Crypto API. Designed for modularity and easy integration into any JavaScript/TypeScript project.

## Table of Contents

- [Overview](#overview)
- [Design Principles](#design-principles)
- [Core Features](#core-features)
- [Architecture Diagram](#architecture-diagram)
- [Module Structure](#module-structure)
- [Security Model](#security-model)
- [Token Flow](#token-flow)
- [API Reference](#api-reference)

---

## Overview

AuthSystem provides enterprise-grade authentication using:

- **RS256 (RSA-SHA256)** asymmetric JWT signing for microservice compatibility
- **Token fingerprinting** (OWASP recommended) to prevent token theft
- **PBKDF2 password hashing** with 600,000 iterations (OWASP 2023 standard)
- **Multi-device session management** with selective revocation
- **Automatic key rotation** with graceful transition periods

### Why Zero Dependencies?

| Benefit | Description |
|---------|-------------|
| **Security** | No supply chain vulnerabilities from third-party packages |
| **Portability** | Works in Node.js, Deno, Bun, Cloudflare Workers, browsers |
| **Auditability** | Complete control over all cryptographic operations |
| **Longevity** | No breaking changes from dependency updates |

---

## Design Principles

1. **Framework Agnostic** — Core logic has no framework dependencies; adapters handle integration
2. **Defense in Depth** — Multiple security layers (fingerprinting, short-lived tokens, rotation)
3. **Fail Secure** — All errors result in authentication denial
4. **Constant Time** — All secret comparisons use timing-safe algorithms
5. **Minimal Surface** — Only expose necessary APIs; internal modules are private

---

## Core Features

### Authentication
- User registration with secure password hashing
- Login with access/refresh token issuance
- Silent token refresh without re-authentication
- Logout (single device or all devices)

### Token Management
- RS256 JWT signing with key ID (`kid`) support
- 15-minute access token lifetime
- 30-day refresh token lifetime with rotation on use
- Token fingerprinting bound to HttpOnly cookie

### Session Management
- Multi-device tracking with device info (user-agent, IP)
- List all active sessions for a user
- Revoke individual sessions or all sessions
- Maximum 10 concurrent sessions per user

### Key Management
- RSA 2048-bit key pair generation
- 90-day key lifetime with automatic rotation
- 7-day grace period for old keys during rotation
- JWKS endpoint for public key distribution

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Client Application                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  Access Token (Memory)  │  Fingerprint Cookie  │  Refresh Token Cookie      │
└────────────┬────────────┴──────────┬───────────┴──────────┬─────────────────┘
             │                       │                      │
             ▼                       ▼                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AuthService                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Login     │  │   Refresh   │  │   Logout    │  │  Register   │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
└─────────┼────────────────┼────────────────┼────────────────┼────────────────┘
          │                │                │                │
          ▼                ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Core Modules                                    │
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │     JWT      │  │  Fingerprint │  │   Session    │  │   Password   │     │
│  │   Module     │  │    Module    │  │   Manager    │  │   Hasher     │     │
│  │              │  │              │  │              │  │              │     │
│  │  • sign      │  │  • generate  │  │  • create    │  │  • hash      │     │
│  │  • verify    │  │  • validate  │  │  • validate  │  │  • verify    │     │
│  │  • decode    │  │              │  │  • revoke    │  │  • serialize │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                 │                 │                 │              │
│         ▼                 ▼                 ▼                 ▼              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         Crypto Foundation                             │   │
│  │  base64url │ hash (SHA-256) │ random │ timing-safe │ universal       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
          │                                               │
          ▼                                               ▼
┌──────────────────────────┐                 ┌──────────────────────────┐
│      Key Storage         │                 │     Session Storage      │
│   (Filesystem: keys/)    │                 │   (Memory / External)    │
│                          │                 │                          │
│  keys/current/           │                 │  • MemoryStore (dev)     │
│    ├── private.pem       │                 │  • Redis (production)    │
│    └── public.jwk        │                 │  • PostgreSQL            │
│  keys/rotated/{kid}/     │                 │                          │
└──────────────────────────┘                 └──────────────────────────┘
```

---

## Module Structure

```
src/
├── crypto/                    # Cryptographic primitives
│   ├── base64url.ts          # URL-safe Base64 encoding/decoding
│   ├── hash.ts               # SHA-256 hashing utilities
│   ├── random.ts             # Secure random generation
│   ├── timing.ts             # Constant-time comparison
│   └── universal.ts          # Cross-runtime crypto access
│
├── keys/                      # RSA key management
│   ├── keyStore.ts           # Key lifecycle management
│   ├── keyRotation.ts        # Automatic rotation logic
│   ├── formats/
│   │   ├── pem.ts            # PEM encoding/decoding
│   │   └── jwk.ts            # JWK format utilities
│   ├── storage/
│   │   └── filesystem.ts     # Filesystem persistence
│   └── distribution/
│       └── jwks.ts           # JWKS endpoint provider
│
├── jwt/                       # JSON Web Token handling
│   ├── sign.ts               # RS256 token creation
│   ├── verify.ts             # Signature & claims validation
│   └── decode.ts             # Parse without verification
│
├── fingerprint/               # Token binding
│   ├── generate.ts           # Random fingerprint creation
│   ├── validate.ts           # Cookie-to-JWT validation
│   └── index.ts              # TokenFingerprinter class
│
├── cookies/                   # Cookie management
│   ├── serializer.ts         # Set-Cookie header creation
│   ├── parser.ts             # Cookie header parsing
│   └── handler.ts            # High-level cookie API
│
├── password/                  # Password security
│   ├── hash.ts               # PBKDF2 hashing
│   ├── verify.ts             # Password verification
│   └── serialize.ts          # PHC string format
│
├── session/                   # Session management
│   ├── manager.ts            # SessionManager class
│   ├── store.ts              # Storage interface
│   └── types.ts              # Session/Device types
│
├── storage/                   # Storage implementations
│   ├── interfaces.ts         # Storage contracts
│   ├── memoryStore.ts        # In-memory session store
│   └── filesystemKeys.ts     # Filesystem key storage
│
├── auth/                      # Main orchestrator
│   └── service.ts            # AuthService class
│
├── types.ts                   # Shared type definitions
└── index.ts                   # Public API exports

keys/                          # Runtime key storage (gitignored)
├── current/
│   ├── private.pem           # Current signing key
│   └── public.jwk            # Current public key
└── rotated/
    └── {kid}/                # Rotated keys (grace period)
        ├── private.pem
        └── public.jwk
```

---

## Security Model

### Token Strategy

| Token Type | Storage | Lifetime | Purpose |
|------------|---------|----------|---------|
| Access Token | Client memory | 15 minutes | API authorization |
| Refresh Token | HttpOnly cookie | 30 days | Obtain new access tokens |
| Fingerprint | HttpOnly cookie | Session | Bind token to browser |

### Why This Approach?

```
┌─────────────────────────────────────────────────────────────────┐
│                     Token Storage Comparison                     │
├─────────────────┬──────────────────┬────────────────────────────┤
│ Strategy        │ XSS Vulnerable   │ CSRF Vulnerable            │
├─────────────────┼──────────────────┼────────────────────────────┤
│ localStorage    │ ✗ Yes            │ ✓ No                       │
│ sessionStorage  │ ✗ Yes            │ ✓ No                       │
│ Memory only     │ ✓ No             │ ✓ No (no persistence)      │
│ HttpOnly Cookie │ ✓ No             │ ✗ Yes (needs protection)   │
├─────────────────┴──────────────────┴────────────────────────────┤
│ OUR APPROACH: Memory + HttpOnly Cookie + Fingerprint            │
│ ✓ XSS Protected: Access token not in DOM-accessible storage     │
│ ✓ CSRF Protected: Fingerprint validation required               │
│ ✓ Theft Protected: Token unusable without fingerprint cookie    │
└─────────────────────────────────────────────────────────────────┘
```

### Token Fingerprinting Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         Token Creation (Login)                            │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Generate 32-byte random value ────────────► Raw Fingerprint          │
│                                                      │                   │
│  2. SHA-256(Raw Fingerprint) ─────────────────► Hash ────► JWT 'fpt'     │
│                                                      │         claim     │
│  3. Raw Fingerprint ──────────────────────────► HttpOnly Cookie          │
│                                                 __Secure-Fpt             │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                       Token Verification (API Request)                    │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Extract JWT from Authorization header                                │
│  2. Extract Raw Fingerprint from __Secure-Fpt cookie                     │
│  3. SHA-256(Raw Fingerprint) ────► Computed Hash                         │
│  4. Constant-time compare: Computed Hash === JWT 'fpt' claim             │
│  5. If match: Token is valid and bound to this browser                   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### Password Hashing

Using PBKDF2 with Web Crypto API (OWASP 2023 compliant):

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Algorithm | PBKDF2-HMAC-SHA256 | NIST approved, native support |
| Iterations | 600,000 | OWASP 2023 minimum for SHA-256 |
| Salt Length | 16 bytes (128 bits) | Unique per password |
| Output Length | 32 bytes (256 bits) | Sufficient entropy |

**Storage Format (PHC String):**
```
$pbkdf2-sha256$600000$<base64url-salt>$<base64url-hash>
```

### Key Rotation

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Key Lifecycle                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Day 0                    Day 83                  Day 90      Day 97     │
│    │                        │                       │           │        │
│    ▼                        ▼                       ▼           ▼        │
│  ┌─────┐                  ┌─────┐                 ┌─────┐    ┌─────┐     │
│  │ NEW │ ──── Active ────►│CHECK│ ── Rotate ────►│ OLD │───►│DELETE│    │
│  └─────┘                  └─────┘                 └─────┘    └─────┘     │
│                                                      │                   │
│                                                      │                   │
│                                            7-day grace period            │
│                                            (accepts old tokens)          │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘

Rotation occurs when 10% of key lifetime remains (day 81 for 90-day keys)
```

### Cookie Security Attributes

```typescript
{
  httpOnly: true,        // Prevent XSS access to cookie
  secure: true,          // HTTPS only (required for __Secure- prefix)
  sameSite: 'Strict',    // Block cross-origin requests
  path: '/',             // Available site-wide
  maxAge: 2592000        // 30 days for refresh token
}
```

Cookie naming follows security prefixes:
- `__Secure-Fpt` — Fingerprint cookie (requires Secure attribute)
- `__Secure-Ref` — Refresh token cookie (requires Secure attribute)

---

## Token Flow

### Registration

```
Client                          Server
  │                               │
  │  POST /auth/register          │
  │  { email, password }          │
  │ ─────────────────────────────►│
  │                               │
  │                               │ 1. Validate input
  │                               │ 2. Check email uniqueness
  │                               │ 3. Hash password (PBKDF2)
  │                               │ 4. Store user
  │                               │
  │  201 Created                  │
  │  { userId, email }            │
  │ ◄─────────────────────────────│
  │                               │
```

### Login

```
Client                          Server
  │                               │
  │  POST /auth/login             │
  │  { email, password }          │
  │ ─────────────────────────────►│
  │                               │
  │                               │ 1. Find user by email
  │                               │ 2. Verify password (PBKDF2)
  │                               │ 3. Generate fingerprint
  │                               │ 4. Create session (store refresh token hash)
  │                               │ 5. Sign access token (RS256 + fingerprint hash)
  │                               │
  │  200 OK                       │
  │  { accessToken, expiresIn }   │
  │  Set-Cookie: __Secure-Fpt=... │
  │  Set-Cookie: __Secure-Ref=... │
  │ ◄─────────────────────────────│
  │                               │
  │  Store accessToken in memory  │
  │                               │
```

### API Request (Protected Resource)

```
Client                          Server
  │                               │
  │  GET /api/resource            │
  │  Authorization: Bearer <JWT>  │
  │  Cookie: __Secure-Fpt=...     │
  │ ─────────────────────────────►│
  │                               │
  │                               │ 1. Extract JWT from header
  │                               │ 2. Verify RS256 signature (lookup key by kid)
  │                               │ 3. Check exp, iss, aud claims
  │                               │ 4. Extract fingerprint from cookie
  │                               │ 5. Hash fingerprint, compare with JWT 'fpt' claim
  │                               │ 6. If valid: authorize request
  │                               │
  │  200 OK                       │
  │  { data }                     │
  │ ◄─────────────────────────────│
  │                               │
```

### Token Refresh

```
Client                          Server
  │                               │
  │  POST /auth/refresh           │
  │  Cookie: __Secure-Ref=...     │
  │ ─────────────────────────────►│
  │                               │
  │                               │ 1. Extract refresh token from cookie
  │                               │ 2. Hash token, lookup session
  │                               │ 3. Validate session (not revoked, not expired)
  │                               │ 4. Generate new fingerprint
  │                               │ 5. Rotate refresh token (new token, invalidate old)
  │                               │ 6. Sign new access token
  │                               │
  │  200 OK                       │
  │  { accessToken, expiresIn }   │
  │  Set-Cookie: __Secure-Fpt=... │
  │  Set-Cookie: __Secure-Ref=... │
  │ ◄─────────────────────────────│
  │                               │
```

### Logout

```
Client                          Server
  │                               │
  │  POST /auth/logout            │
  │  Cookie: __Secure-Ref=...     │
  │ ─────────────────────────────►│
  │                               │
  │                               │ 1. Extract session from refresh token
  │                               │ 2. Revoke session
  │                               │ 3. Clear cookies
  │                               │
  │  200 OK                       │
  │  Set-Cookie: __Secure-Fpt=; Max-Age=0
  │  Set-Cookie: __Secure-Ref=; Max-Age=0
  │ ◄─────────────────────────────│
  │                               │
  │  Clear accessToken from memory│
  │                               │
```

---

## API Reference

### AuthService

The main orchestrator that combines all modules.

```typescript
class AuthService {
  constructor(options: AuthServiceOptions)
  
  // User registration
  register(email: string, password: string): Promise<RegisterResult>
  
  // User login - returns tokens and cookies
  login(email: string, password: string, deviceInfo: DeviceInfo): Promise<LoginResult>
  
  // Refresh access token
  refresh(refreshToken: string): Promise<RefreshResult>
  
  // Logout current session
  logout(sessionId: string): Promise<void>
  
  // Logout all sessions for user
  logoutAll(userId: string, exceptSessionId?: string): Promise<number>
  
  // Get all active sessions for user
  getSessions(userId: string): Promise<Session[]>
  
  // Verify access token and fingerprint
  verifyRequest(authHeader: string, cookieHeader: string): Promise<VerifyResult>
}
```

### Response Formats

**Login Response:**
```typescript
{
  accessToken: string,    // JWT (store in client memory)
  expiresIn: number,      // Seconds until expiry (900 = 15 min)
  tokenType: 'Bearer',
  user: {
    id: string,
    email: string
  }
}
// + Set-Cookie headers for __Secure-Fpt and __Secure-Ref
```

**Refresh Response:**
```typescript
{
  accessToken: string,
  expiresIn: number,
  tokenType: 'Bearer'
}
// + Updated Set-Cookie headers
```

**Session List Response:**
```typescript
{
  sessions: [
    {
      id: string,
      deviceInfo: {
        userAgent: string,
        ip: string,
        deviceName?: string
      },
      createdAt: string,       // ISO 8601
      lastAccessedAt: string,  // ISO 8601
      isCurrent: boolean
    }
  ]
}
```

### JWT Claims

```typescript
{
  // Standard claims
  sub: string,      // User ID
  iat: number,      // Issued at (Unix timestamp)
  exp: number,      // Expiration (Unix timestamp)
  jti: string,      // JWT ID (for revocation)
  iss: string,      // Issuer
  aud: string,      // Audience
  
  // Custom claims
  fpt: string,      // Fingerprint hash (SHA-256 of raw fingerprint)
  sid: string       // Session ID
}
```

### JWKS Endpoint

Serves public keys at `/.well-known/jwks.json`:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "key_abc123",
      "n": "<modulus>",
      "e": "AQAB"
    }
  ]
}
```

---

## Configuration

### AuthServiceOptions

```typescript
interface AuthServiceOptions {
  // JWT settings
  jwt: {
    issuer: string,              // e.g., 'https://auth.example.com'
    audience: string,            // e.g., 'https://api.example.com'
    accessTokenLifetime: number  // Seconds (default: 900)
  },
  
  // Session settings
  session: {
    refreshTokenLifetime: number, // Seconds (default: 2592000 = 30 days)
    maxSessionsPerUser: number,   // Default: 10
    store: SessionStore           // Storage implementation
  },
  
  // Key settings
  keys: {
    directory: string,           // e.g., './keys'
    keyLifetimeMs: number,       // Default: 90 days
    rotationGracePeriodMs: number // Default: 7 days
  },
  
  // Cookie settings
  cookies: {
    secure: boolean,             // Default: true (HTTPS only)
    sameSite: 'Strict' | 'Lax',  // Default: 'Strict'
    domain?: string              // Optional domain restriction
  }
}
```

---

## Integration Examples

### Express.js

```typescript
import { AuthService } from '@authsystem/core';
import express from 'express';

const auth = new AuthService({ /* options */ });
const app = express();

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const deviceInfo = {
    userAgent: req.headers['user-agent'],
    ip: req.ip
  };
  
  const result = await auth.login(email, password, deviceInfo);
  
  // Set cookies
  res.setHeader('Set-Cookie', result.cookies);
  
  // Return access token in body
  res.json({
    accessToken: result.accessToken,
    expiresIn: result.expiresIn,
    tokenType: 'Bearer'
  });
});

// Protected route middleware
async function authenticate(req, res, next) {
  const result = await auth.verifyRequest(
    req.headers.authorization,
    req.headers.cookie
  );
  
  if (!result.valid) {
    return res.status(401).json({ error: result.error });
  }
  
  req.user = result.user;
  next();
}
```

### Fastify

```typescript
import { AuthService } from '@authsystem/core';
import Fastify from 'fastify';

const auth = new AuthService({ /* options */ });
const fastify = Fastify();

fastify.post('/auth/login', async (request, reply) => {
  const { email, password } = request.body;
  const deviceInfo = {
    userAgent: request.headers['user-agent'],
    ip: request.ip
  };
  
  const result = await auth.login(email, password, deviceInfo);
  
  for (const cookie of result.cookies) {
    reply.header('Set-Cookie', cookie);
  }
  
  return {
    accessToken: result.accessToken,
    expiresIn: result.expiresIn,
    tokenType: 'Bearer'
  };
});
```

### Client-Side (Vanilla JS)

```typescript
class AuthClient {
  private accessToken: string | null = null;
  private refreshTimeout: number | null = null;
  
  async login(email: string, password: string): Promise<void> {
    const response = await fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include', // Important: sends/receives cookies
      body: JSON.stringify({ email, password })
    });
    
    const { accessToken, expiresIn } = await response.json();
    this.accessToken = accessToken;
    this.scheduleRefresh(expiresIn);
  }
  
  async fetch(url: string, options: RequestInit = {}): Promise<Response> {
    return fetch(url, {
      ...options,
      credentials: 'include',
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${this.accessToken}`
      }
    });
  }
  
  private scheduleRefresh(expiresIn: number): void {
    // Refresh 1 minute before expiry
    const refreshIn = (expiresIn - 60) * 1000;
    
    this.refreshTimeout = setTimeout(async () => {
      const response = await fetch('/auth/refresh', {
        method: 'POST',
        credentials: 'include'
      });
      
      if (response.ok) {
        const { accessToken, expiresIn } = await response.json();
        this.accessToken = accessToken;
        this.scheduleRefresh(expiresIn);
      } else {
        // Session expired, redirect to login
        this.accessToken = null;
        window.location.href = '/login';
      }
    }, refreshIn);
  }
  
  async logout(): Promise<void> {
    await fetch('/auth/logout', {
      method: 'POST',
      credentials: 'include'
    });
    
    this.accessToken = null;
    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
    }
  }
}
```

---

## Runtime Compatibility

| Runtime | Version | Support |
|---------|---------|---------|
| Node.js | 18+ | ✅ Full |
| Node.js | 16-17 | ✅ Full (with `crypto.webcrypto`) |
| Deno | 1.0+ | ✅ Full |
| Bun | 1.0+ | ✅ Full |
| Cloudflare Workers | - | ✅ Full |
| Modern Browsers | - | ✅ Full |

The `universal.ts` module provides a unified crypto interface:

```typescript
const crypto = getUniversalCrypto();
// Works in all runtimes, returns Web Crypto API compatible interface
```

---

## File Permissions

The `keys/` directory should have restricted permissions:

```bash
chmod 700 keys/
chmod 600 keys/current/private.pem
chmod 644 keys/current/public.jwk
```

Add to `.gitignore`:
```
keys/
```

---

## Next Steps

1. **Implement Core Modules** — Build crypto foundation and key management
2. **Add Framework Adapters** — Create middleware for Express, Fastify, Hono
3. **Build Client Libraries** — React hooks, Vue composables
4. **Add Storage Adapters** — Redis, PostgreSQL session stores
5. **Testing** — Unit tests, integration tests, security audit
